cat > /root/.bash_logout <<EOF
history -w # Write bash history. Otherwise bash would be killed by poweroff without having written history

echo "bash logout for tty: \$(tty) ..."

# Turn off the VM when the last user logs out.
if [[ "\$(tty)" == "/dev/hvc0" ]]; then
  # we are the primary terminal
  if [[ "\$(who | wc -l)" == "1" ]]; then
    # we are the last open terminal
    echo "VM powering off..."
    systemctl poweroff
  else
    echo ""
    echo "VM not powering off as there are terminals connected"
  fi
else
  # we are a ssh session
  if [[ "\$(who | wc -l)" == "1" ]]; then
    # we are the last open terminal
    echo "VM powering off..."
    systemctl poweroff
    # As part of the logout, write the OSC 9999 sentinel to the tty
    # The proxy detects the sentinel and closes the client socket, which causes
    # attach_console to exit via normal socket-close detection.
    printf '\033]9999\007' > "\$(tty)"
  else
    echo "Detaching..."
    # As part of the logout, write the OSC 9999 sentinel to the tty
    # The proxy detects the sentinel and closes the client socket, which causes
    # attach_console to exit via normal socket-close detection.
    printf '\033]9999\007' > "\$(tty)"
  fi
fi
EOF
