


## Distro flavors

Debian 

> generic: Should run in any environment using cloud-init, for e.g. OpenStack, DigitalOcean and also on bare metal.
> genericcloud: Identical to generic but with a reduced set of hardware drivers in the kernel. If it does not work for your use case, you should use the generic images.
> nocloud: Does not run cloud-init and boots directly to a root prompt. Useful for local VM instantiation with tools like QEMU.



## Booting

there are two ways to boot:

1. From a disk image which contains bootloader.

2. With a kernel (distributed as a compressed `vmlinuz` which needs to be decompressed first to run) and ramdisk (`initrd` --- "initial ram disk", I guess).
Specifying these which allows for command line arguments to specify where to output boot logs

"console=hvc0",


## How can you configure a VM?

I'm familiar with three ways of automated VM configuration:

### SSH

If the downloaded image is configured to automatically set up networking and start and SSH server, you can just keep trying to login, then run your provisioning commands:

```sh

# SSH args to disable noise about keys and stuff
SSH_ARGS="-o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/dev/null -p $SSH_PORT"

until ssh $SSH_ARGS -o ConnectTimeout=1 user@vm-address true 2>/dev/null; do
    echo -n "."
    sleep 1
done

ssh $SSH_ARGS user@vm-address 'bash -s' <<EOF
  # provisioning commands go here
EOF
```

However, none of Debian's official images have SSH and a default username/password, so I couldn't use this approach.



### Cloud-init

Here you put configuration data in YAML files, put those into a disk image, then mount this disk image to the VM, which uses it on first boot to configure itself.
For example, here's setting up a new user named `user` with no password

```sh
mkdir -p cidata

cat > cidata/meta-data << 'EOF'
instance-id: debian-vm
local-hostname: debian
EOF

cat > cidata/user-data << 'EOF'
#cloud-config
users:
  - name: user
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    lock_passwd: false
ssh_pwauth: true
runcmd:
  - sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords yes/' /etc/ssh/sshd_config
  - passwd -d user
  - systemctl restart sshd
EOF

hdiutil makehybrid -o seed.img -iso -joliet -default-volume-name cidata cidata/ > /dev/null 2>&1
rm -rf cidata
```

Originally I steered away from cloud-init because it seemed complicated.
In particular, when I booted some Ubuntu VMs they tried to make all sorts of network requests to possible remote configuration servers (which I wasn't running).

There was also `systemd-networkd-wait-online.service` which blocks booting until it times out after 2.5 minutes, but only when my host machine was on a VPN.
(This one took me quite a while to figure out!)

Overall this didn't spark joy and felt too heavy, so I decided to go old schhool.

### Console

The other approach I explored was using the Debian `nocloud` image, which boots very quickly (no cloud-init stuff!) and allows login via `root` without a password.

Automating this is tricky because the host has to wait until the VM is booted and waiting at the login prompt.

There's some juggling of file descriptors here, since you want:

1. the VM's console wired up to the terminal (so you can see output and type stuff)
2. the automated provisioning to *also* be able to see output and "type" stuff.


But the idea is to have the provisioning system wait until it sees the VM's output end with `login:`, and then it should duplicate the console input file descriptor so that it can also write some stuff there:
```rust
let dup_fd = libc::dup(console_stdin);
if dup_fd < 0 {
    eprintln!("Failed to dup fd: {}", io::Error::last_os_error());
    return;
}
let mut stdin = File::from_raw_fd(dup_fd);

let mut do_write = |payload: &str| {
    if let Err(e) = stdin.write_all(payload.as_bytes()) {
        eprintln!("Failed to write payload to VM serial: {}", e);
    }
    let _ = stdin.flush();
};

// first login, waiting a bit for the VM's prompt to come up (timeout works fine, but ideally this would wait for expected prompt characters to show up)
do_write("root\n");
std::thread::sleep(Duration::from_millis(500));

// write in the provisioning script and run it
do_write(&format!(
    "cat >/root/provision.sh <<'EOF'\n{script}EOF\nchmod +x /root/provision.sh\n/root/provision.sh\n",
));
```




## Other learnings

Apple's filesystem supports sparse files, so resizing a file:

```rust
let file = fs::OpenOptions::new().write(true).open(path)?;
file.set_len(size_bytes)?;
```

won't actually consume any disk space until the new parts of the file are written to.
You can run `ls -lsh some-file` to see the used blocks (first column) compared to the allocated space.
For example, this file is sized as 10GB but only uses about 2GB of blocks:

    2382272 -rw-r--r--@ 1 klynagh  staff    10G Jan 15 22:08 some-file
