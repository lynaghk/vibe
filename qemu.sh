#!/bin/bash
set -eu

RAM="2G"
CPUS="4"
DISK_SIZE="10G"
SSH_PORT="2222"
SSH_ARGS="-o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -p $SSH_PORT"

QEMU_PREFIX=$(dirname $(dirname $(realpath $(which qemu-system-aarch64))))


CURRENT_DIR="$(pwd -P)"
CURRENT_BASENAME="$(basename $CURRENT_DIR)"

# The VM shouldn't be allowed to modify the .git subdirectory (if any).
SANDBOX_RULES="
(version 1)
(allow default)
(deny file-read* file-write* (subpath \"$CURRENT_DIR/.git\"))
"


# System-wide cache directory to hold the downloaded distro image and configured base image.
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/vibetron"
mkdir -p "$CACHE_DIR"

# cache shared across all guest machines for things installed via mise. (can't share with host because mac/linux. https://mise.jdx.dev/directories.html#local-share-mise)
GUEST_MISE_CACHE="$CACHE_DIR/.guest-mise-cache"
mkdir -p "$GUEST_MISE_CACHE"

INSTANCE_DIR="$CURRENT_DIR/.vibetron"
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
    echo "Creating VM $derived_disk"
    dir=$(dirname "$derived_disk")
    qemu-img create -f qcow2 -b "$template_disk" -F qcow2 "$derived_disk" "$DISK_SIZE" > /dev/null 2>&1 
    cp "$QEMU_PREFIX/share/qemu/edk2-aarch64-code.fd" "$dir/efi.img"
    dd if=/dev/zero of="${dir}/efi_vars.img" bs=1m count=64 > /dev/null 2>&1 
}



wait_until_guest_ssh_available(){
    echo -n "Connecting to VM"
    until ssh $SSH_ARGS -o ConnectTimeout=1 user@localhost true 2>/dev/null; do
        echo -n "."
        sleep 1
    done
    echo ""
}


# Create vibetron configured machine and disk
if [ ! -f "$CONFIGURED_DISK" ]; then

    echo "========================================"
    echo "Configuring vibetron base image."
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
  - sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
  - passwd -d user
  - systemctl restart sshd
EOF

    hdiutil makehybrid -o seed.img -iso -joliet -default-volume-name cidata cidata/ > /dev/null 2>&1
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
        -serial mon:stdio > /dev/null 2>&1 &

    trap 'wait $!' EXIT
    
    wait_until_guest_ssh_available
    
    ssh $SSH_ARGS user@localhost 'bash -s' <<'EOF'
    #!/bin/bash
    set -eux

    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
            build-essential                         \
            pkg-config                              \
            libssl-dev                              \
            curl                                    \
            git                                     \
            ripgrep

    # Install mise
    curl https://mise.run | sh
    echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc

    sudo su

    # Disable stuff to speed up future boots
    touch /etc/cloud/cloud-init.disabled
    systemctl disable apt-daily.timer apt-daily-upgrade.timer man-db.timer e2scrub_all.timer fstrim.timer unattended-upgrades
    systemctl mask systemd-timesyncd
    systemctl mask apparmor

    shutdown now
EOF

    popd
fi



if [ ! -f "$INSTANCE_DISK" ]; then
    createVM "$CONFIGURED_DISK" "$INSTANCE_DISK"
fi

cd "$INSTANCE_DIR"

echo "Booting VM at $INSTANCE_DIR"

sandbox-exec -p "$SANDBOX_RULES"                                                                             \
             qemu-system-aarch64                                                                             \
             -M virt                                                                                         \
             -accel hvf                                                                                      \
             -cpu host                                                                                       \
             -smp "$CPUS"                                                                                    \
             -m "$RAM"                                                                                       \
             -drive if=pflash,format=raw,file="efi.img",readonly=on                                          \
             -drive if=pflash,format=raw,file="efi_vars.img"                                                 \
             -drive file="$INSTANCE_DISK",if=virtio                                                          \
             -device virtio-net-pci,netdev=net0                                                              \
             -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22                                               \
             -nographic                                                                                      \
             -virtfs local,security_model=mapped-xattr,path="$HOME/.cargo/registry",mount_tag=cargo_registry \
             -virtfs local,security_model=mapped-xattr,path="$GUEST_MISE_CACHE",mount_tag=mise_cache         \
             -virtfs local,security_model=mapped-xattr,path="$CURRENT_DIR",mount_tag=current_dir             \
             -serial mon:stdio > /dev/null 2>&1 &


trap 'wait $!' EXIT

wait_until_guest_ssh_available


ssh $SSH_ARGS user@localhost 'bash -s' <<EOF

    # setup mounts

    mkdir -p .cargo/registry
    sudo mount -t 9p -o trans=virtio,version=9p2000.L cargo_registry .cargo/registry
    sudo chown user:user .cargo/registry

    mkdir -p .local/share/mise
    sudo mount -t 9p -o trans=virtio,version=9p2000.L mise_cache .local/share/mise
    sudo chown user:user .local/share/mise

    mkdir -p "$CURRENT_BASENAME"
    sudo mount -t 9p -o trans=virtio,version=9p2000.L current_dir "$CURRENT_BASENAME"
    sudo chown user:user "$CURRENT_BASENAME"


    # setup VM-wide mise config
    mkdir -p .config/mise/
    
    cat > .config/mise/config.toml <<MISE
        [settings]
        # Always use the venv created by uv, if available in directory
        python.uv_venv_auto = true
        experimental = true
        idiomatic_version_file_enable_tools = ["rust"]

        [tools]
        uv = "0.9.25"
        node = "24.13.0"
        "npm:@openai/codex" = "latest"
MISE
    
EOF


# open an interactive shell in the current_dir on the guest
ssh $SSH_ARGS -t user@localhost "cd '$CURRENT_BASENAME' && exec /bin/bash -l"

# done, shutdown the VM.
ssh $SSH_ARGS user@localhost "sudo shutdown now"
