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

# Don't display "Last login from ..." on logins
touch .hushlogin

cat > /root/.bashrc <<EOF
# Set this env var so claude doesn't complain about running as root.
export IS_SANDBOX=1

# Set this environment variable to prevent the Gemini CLI from failing to identify the sandbox command
export GEMINI_SANDBOX=false

# Enable true color support in the terminal
export COLORTERM=truecolor

# Hide commands beginning with space from the history
export HISTCONTROL=ignorespace

# Unlimited bash history
export HISTFILESIZE=
export HISTSIZE=

# Use append mode for history
shopt -s histappend
# Write history after every command
PROMPT_COMMAND+=("history -a")
EOF

# Shutdown the VM when you logout
cat > /root/.bash_logout <<EOF

if [[ "/dev/hvc0" == "\$(tty)" ]]; then
  # Sync file system before VM poweroff. Otherwise we may lose recent bash history
  sync --file-system /root
  printf 'a' > /dev/hvc1
  sleep 0.1
elif [[ "/dev/hvc2" == "\$(tty)" ]]; then
  sync --file-system /root
  printf 'b' > /dev/hvc1
  sleep 0.1
elif [[ "/dev/hvc4" == "\$(tty)" ]]; then
  sync --file-system /root
  printf 'c' > /dev/hvc1
  sleep 0.1
elif [[ "/dev/hvc6" == "\$(tty)" ]]; then
  sync --file-system /root
  printf 'd' > /dev/hvc1
  sleep 0.1
fi
EOF

for d in hvc0 hvc2 hvc4 hvc6; do
  mkdir -p /etc/systemd/system/serial-getty@${d}.service.d
  printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --noclear --autologin root - linux\n' \
> /etc/systemd/system/serial-getty@${d}.service.d/autologin.conf;
done

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
    "npm:@mariozechner/pi-coding-agent" = "latest"
MISE

touch .config/mise/mise.lock
mise install

# Done provisioning, power off the VM
systemctl poweroff
