#!/bin/bash
set -euo pipefail

command -v qemu-img &>/dev/null || { echo "qemu-img required. Run: sudo port install qemu"; exit 1; }

mkdir -p target

ARCH=$(uname -m)
if [[ "$ARCH" == "arm64" ]]; then
    DEBIAN_ARCH="arm64"
else
    DEBIAN_ARCH="amd64"
fi

BASE_URL="https://cloud.debian.org/images/cloud/bookworm/latest"

if [[ ! -f target/vm-disk.raw ]]; then
    if [[ ! -f target/debian-bookworm-cloudimg.qcow2 ]]; then
        echo "Downloading disk image..."
        curl -L -o target/debian-bookworm-cloudimg.qcow2 "${BASE_URL}/debian-12-generic-${DEBIAN_ARCH}.qcow2"
    fi
    echo "Converting to raw..."
    qemu-img convert -f qcow2 -O raw target/debian-bookworm-cloudimg.qcow2 target/vm-disk.raw
else
    echo "target/vm-disk.raw already exists, skipping"
fi

# Extract kernel and initrd from the disk image
if [[ ! -f target/vmlinuz ]] || [[ ! -f target/initrd ]]; then
    echo "Extracting kernel and initrd from disk image..."
    # Mount the raw disk to extract kernel/initrd
    # For now, download them separately from Debian
    KERNEL_URL="https://deb.debian.org/debian/dists/bookworm/main/installer-${DEBIAN_ARCH}/current/images/netboot/debian-installer/${DEBIAN_ARCH}"
    curl -L -o target/vmlinuz "${KERNEL_URL}/linux"
    curl -L -o target/initrd "${KERNEL_URL}/initrd.gz"
else
    echo "target/vmlinuz and target/initrd already exist, skipping"
fi

cat > target/entitlements.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.virtualization</key>
    <true/>
<key>com.apple.security.hypervisor</key>
<true/>
</dict>
</plist>
EOF

echo "Building..."
cargo build --release

echo "Signing binary..."
codesign --entitlements target/entitlements.plist --force -s - target/release/vibebox

cd target
#lldb ./release/vibebox

./release/vibebox
