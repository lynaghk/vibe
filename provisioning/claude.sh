#!/bin/bash
# Install Anthropic's Claude.
set -euxo pipefail

# Set this env var so claude doesn't complain about running as root.
echo "export IS_SANDBOX=1" >> .bashrc

tool='    "npm:@anthropic-ai/claude-code" = { version = "latest", npm-args = "--ignore-scripts=false" }'
echo "$tool" >> .config/mise/config.toml

mise install
