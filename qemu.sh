#!/bin/sh
set -eu

VM_DIR="${1:-$HOME/debian-vm}"
RAM="2G"
CPUS="4"
DISK_SIZE="10G"
SSH_PORT="2222"

mkdir -p "$VM_DIR"
cd "$VM_DIR"

# Download Debian cloud image (pre-installed, no installer needed)
if [ ! -f debian.qcow2 ]; then
  curl -LO https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2
  cp debian-12-generic-arm64.qcow2 debian.qcow2
  qemu-img resize debian.qcow2 "$DISK_SIZE"
fi

# Get UEFI firmware
if [ ! -f edk2-aarch64-code.fd ]; then
  curl -LO https://releases.linaro.org/components/kernel/uefi-linaro/latest/release/qemu64/QEMU_EFI.fd
  dd if=/dev/zero of=edk2-aarch64-code.fd bs=1m count=64
  dd if=QEMU_EFI.fd of=edk2-aarch64-code.fd conv=notrunc
fi

if [ ! -f edk2-arm-vars.fd ]; then
  dd if=/dev/zero of=edk2-arm-vars.fd bs=1m count=64
fi

# Cloud-init config to set password
if [ ! -f seed.img.iso ]; then
  cat > meta-data << 'EOF'
instance-id: debian-vm
local-hostname: debian
EOF

  cat > user-data << 'EOF'
#cloud-config
users:
  - name: user
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: password
ssh_pwauth: true
EOF

  # Create cloud-init seed image
  if command -v mkisofs >/dev/null 2>&1; then
    mkisofs -output seed.img -volid cidata -joliet -rock user-data meta-data
  elif command -v hdiutil >/dev/null 2>&1; then
    mkdir -p cidata
    cp user-data meta-data cidata/
    hdiutil makehybrid -o seed.img -iso -joliet -default-volume-name cidata cidata/
    rm -rf cidata
  fi
fi

echo "Starting VM..."
echo "SSH: ssh -p $SSH_PORT user@localhost (password: password)"
echo "Console login: user / password"
echo "Quit: Ctrl-A X"
echo ""

qemu-system-aarch64 \
  -M virt \
  -accel hvf \
  -cpu host \
  -smp "$CPUS" \
  -m "$RAM" \
  -drive if=pflash,format=raw,file=edk2-aarch64-code.fd,readonly=on \
  -drive if=pflash,format=raw,file=edk2-arm-vars.fd \
  -drive file=debian.qcow2,if=virtio \
  -drive file=seed.img.iso,if=virtio,format=raw \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
  -nographic \
  -serial mon:stdio
