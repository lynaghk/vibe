cat > /root/.bash_logout <<EOF
history -w
USER_COUNT="\$(who | wc -l)"

if [[ "\${VIBE_POWEROFF:-true}" == "false" ]]; then
  # do nothing on initial boot logout
  :
else
  if [[ "\${USER_COUNT}" == "1" ]]; then
    echo "VM powering off..."
    systemctl poweroff
    sleep 60
  else
    # disconnect client
    printf '\033]9999\007' > "\$(tty)"
  fi
fi
EOF
