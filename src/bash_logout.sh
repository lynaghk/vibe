cat > /root/.bash_logout <<EOF
history -w
#USER_COUNT="\$(who | wc -l)"

if [[ "\${VIBE_POWEROFF:-true}" == "false" ]]; then
  # do nothing on initial boot logout
  :
else
#  printf 'x' > "/dev/hvc1"
#  if [[ "\${USER_COUNT}" == "1" ]]; then
#    echo "VM powering off..."
#    systemctl poweroff
     Tell the proxy to wait for the VM to finish shutting down before disconnecting
#    printf '\033]9998\007' > "\$(tty)"
#  else
     disconnect client
#    printf '\033]9999\007' > "\$(tty)"
#  fi
fi
EOF
