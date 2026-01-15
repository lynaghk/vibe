#!/bin/bash
set -eux

apt-get update
apt-get install -y --no-install-recommends \
        build-essential                         \
        pkg-config                              \
        libssl-dev                              \
        curl                                    \
    git                                     \
    ripgrep

# Create vibe user and configure sudo
if ! id vibe >/dev/null 2>&1; then
    useradd -m -s /bin/bash vibe
fi
passwd -d vibe || true
echo "vibe ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/90-vibe

# Install mise for vibe and root
su - vibe -c 'curl https://mise.run | sh'
su - vibe -c 'echo '\''eval "$(~/.local/bin/mise activate bash)"'\'' >> ~/.bashrc'

curl https://mise.run | sh
echo 'eval "$(~/.local/bin/mise activate bash)"' >> /root/.bashrc

shutdown now
