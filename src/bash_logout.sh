cat > /root/.bash_logout <<EOF

if [[ "/dev/hvc0" == "\$(tty)" ]]; then
  printf 'a' > /dev/hvc1
  sleep 0.1
elif [[ "/dev/hvc2" == "\$(tty)" ]]; then
  printf 'b' > /dev/hvc1
  sleep 0.1
elif [[ "/dev/hvc4" == "\$(tty)" ]]; then
  printf 'c' > /dev/hvc1
  sleep 0.1
elif [[ "/dev/hvc6" == "\$(tty)" ]]; then
  printf 'd' > /dev/hvc1
  sleep 0.1
fi

EOF
