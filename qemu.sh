#!/bin/bash
set -eu


RAM="2G"
CPUS="4"
DISK_SIZE="10G"
SSH_PORT="2222"

QEMU_PREFIX=$(dirname $(dirname $(realpath $(which qemu-system-aarch64))))

# System-wide cache directory to hold the downloaded distro image and configured base image.
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/vibetron"
mkdir -p "$CACHE_DIR"


CURRENT_DIR="$(pwd -P)"
INSTANCE_DIR="$CURRENT_DIR/.vibe"
mkdir -p "$INSTANCE_DIR" && cd "$INSTANCE_DIR"


DOWNLOADED_DISK="$CACHE_DIR/downloaded.qcow2"
CONFIGURED_DISK="$CACHE_DIR/configured.qcow2"
INSTANCE_DISK="$INSTANCE_DIR/instance.qcow2"

if [ ! -f "$DOWNLOADED_DISK" ]; then
    curl -L "https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2" \
         -o "$DOWNLOADED_DISK"

    # TODO: qemu 9.1.1 seems to still pass through writes to this from the derived images, so have to force it to not do that. =(
    chmod -w "$DOWNLOADED_DISK"
fi

createVM() {
    template_disk="$1"
    derived_disk="$2"
    dir=$(dirname "$derived_disk")
    qemu-img create -f qcow2 -b "$template_disk" -F qcow2 "$derived_disk" "$DISK_SIZE"
    cp "$QEMU_PREFIX/share/qemu/edk2-aarch64-code.fd" "$dir/efi.img"
    dd if=/dev/zero of="${dir}/efi_vars.img" bs=1m count=64
}


# Create vibetron configured machine and disk
if [ ! -f "$CONFIGURED_DISK" ]; then

    echo "========================================"
    echo "Configuring shared vibetron image."
    echo "========================================"

    pushd "$CACHE_DIR"

    createVM "$DOWNLOADED_DISK" "$CONFIGURED_DISK"

    mkdir -p cidata

    cat > cidata/meta-data << 'EOF'
instance-id: debian-vm
local-hostname: debian
EOF

    cat > cidata/user-data << 'EOF'
#cloud-config
users:
  - name: user
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
ssh_pwauth: true
runcmd:
  - mkdir -p /mnt/host
  - mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host || true
  - sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
  - passwd -d user
  - systemctl restart sshd
  - touch /etc/cloud/cloud-init.disabled
  - systemctl disable apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer fstrim.timer unattended-upgrades
  - systemctl mask systemd-timesyncd
  - systemctl mask apparmor
EOF
    hdiutil makehybrid -o seed.img -iso -joliet -default-volume-name cidata cidata/
    rm -rf cidata



    qemu-system-aarch64 \
        -M virt \
        -accel hvf \
        -cpu host \
        -smp "$CPUS" \
        -m "$RAM" \
        -drive if=pflash,format=raw,file="efi.img",readonly=on \
        -drive if=pflash,format=raw,file="efi_vars.img" \
        -drive file="$CONFIGURED_DISK",if=virtio \
        -drive file="seed.img.iso",if=virtio,format=raw \
        -device virtio-net-pci,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
        -nographic \
        -serial mon:stdio


    popd
fi


# The VM shouldn't be allowed to modify the .git subdirectory (if any).
SANDBOX_RULES="
(version 1)
(allow default)
(deny file-read* file-write* (subpath \"$CURRENT_DIR/.git\"))
"

sandbox-exec -p "$SANDBOX_RULES" \
             qemu-system-aarch64 \
             -M virt \
             -accel hvf \
             -cpu host \
             -smp "$CPUS" \
             -m "$RAM" \
             -drive if=pflash,format=raw,file="efi.img",readonly=on \
             -drive if=pflash,format=raw,file="efi_vars.img" \
             -drive file="disk.qcow2",if=virtio \
             -drive file="seed.img.iso",if=virtio,format=raw \
             -device virtio-net-pci,netdev=net0 \
             -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
             -nographic \
             -fsdev local,id=host_dev,path="$CURRENT_DIR",security_model=mapped-xattr \
             -device virtio-9p-pci,fsdev=host_dev,mount_tag=hostshare \
             -serial mon:stdio

#-serial mon:stdio
#-serial mon:stdio > /dev/null 2>&1 &

#If you want to interact with the console later, consider `-serial unix:/tmp/qemu-serial.sock,server,nowait` instead, then connect with `socat - UNIX-CONNECT:/tmp/qemu-serial.sock` when needed.

QEMU_PID=$!

until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=1 -p 2222 user@localhost true 2>/dev/null; do
    echo "loop"
    sleep 1
done

ssh -p 2222 user@localhost
