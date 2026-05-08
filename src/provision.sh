#!/bin/bash
set -euxo pipefail

# Don't wait too long for slow mirrors.
echo 'Acquire::http::Timeout "2";' | tee /etc/apt/apt.conf.d/99timeout
echo 'Acquire::https::Timeout "2";' | tee -a /etc/apt/apt.conf.d/99timeout
echo 'Acquire::Retries "2";' | tee -a /etc/apt/apt.conf.d/99timeout

apt-get update
apt-get install -y --no-install-recommends      \
        cloud-guest-utils                       \
        build-essential                         \
        pkg-config                              \
        libssl-dev                              \
        curl                                    \
        git                                     \
        tmux                                    \
        ripgrep


# Expand disk partition
growpart /dev/vda 1

# Expand filesystem
resize2fs /dev/vda1

# Set hostname to vibe" so it's clear that you're inside the VM.
hostnamectl set-hostname vibe

# Set this env var so claude doesn't complain about running as root.'
echo "export IS_SANDBOX=1" >> .bashrc

# Set this environment variable to prevent the Gemini CLI from failing to identify the sandbox command
echo "export GEMINI_SANDBOX=false" >> .bashrc

# Enable true color support in the terminal
echo "export COLORTERM=truecolor" >> .bashrc

# Hide commands beginning with space from the history
echo "export HISTCONTROL=ignorespace" >> .bashrc

# Unlimited bash history
echo "export HISTFILESIZE=" >> .bashrc
echo "export HISTSIZE=" >> .bashrc

# Shutdown the VM when you logout
cat > .bash_logout <<EOF
history -w # Write bash history. Otherwise bash would be killed by poweroff without having written history

# Only shutdown if tmux isn't running
if ! tmux list-sessions &> /dev/null; then
    systemctl poweroff
    sleep 100 # sleep here so that we don't see the login screen flash up before the shutdown.
fi
EOF


# Install Rust
curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --component "rustfmt,clippy"


# Install Mise
curl https://mise.run | sh
echo 'eval "$(~/.local/bin/mise activate bash)"' >> .bashrc

export PATH="$HOME/.local/bin:$PATH"
eval "$(mise activate bash)"

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
    "npm:@anthropic-ai/claude-code" = "latest"
    "npm:@google/gemini-cli" = "latest"
    "npm:@earendil-works/pi-coding-agent" = "latest"
MISE

touch .config/mise/mise.lock
mise install

# Done provisioning, power off the VM
systemctl poweroff
