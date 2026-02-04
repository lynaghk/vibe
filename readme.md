Vibe is a quick, zero-configuration way to spin up a Linux virtual machine on Mac to sandbox LLM agents:

```
$ cd my-project
$ vibe

░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
   ░▒▓██▓▒░  ░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░

Host                                      Guest                    Mode
----------------------------------------  -----------------------  ----------
/Users/dev/work/my-project                /root/my-project         read-write
/Users/dev/.cache/vibe/.guest-mise-cache  /root/.local/share/mise  read-write
/Users/dev/.m2                            /root/.m2                read-write
/Users/dev/.cargo/registry                /root/.cargo/registry    read-write
/Users/dev/.codex                         /root/.codex             read-write
/Users/dev/.claude                        /root/.claude            read-write

root@vibe:~/my-project#
```

On my M1 MacBook Air it takes ~10 seconds to boot.


Dependencies:

- An ARM-based Mac running MacOS 13 (Ventura) or higher.
- A network connection is required on the first run to download and configure the Debian Linux base image.
- That's it!


## Why use Vibe?

- LLM agents are more fun to use with `--yolo`, since they're not always interrupting you to approve their commands.
- Sandboxing the agent in a VM lets it install/remove whatever tools its lil' transformer heart desires, *without* wrecking your actual machine.
- You control what the agent (and thus the upstream LLM provider) can actually see, by controlling exactly what's shared into the VM sandbox.
  (This project was inspired by me running `codex` *without* `--yolo` and seeing it reading files outside of the directory I started it in --- not cool, bro.)

I'm using virtual machines rather than containers because:

- Virtualization is more secure against malicious escapes than containers or the MacOS sandbox framework.
- Containers on MacOS require spinning up a virtual machine anyway.

Finally, as a matter of taste and style:

- The binary is < 1 MB.
- I wrote the entire README myself, 100% with my human brain.
- The entire implementation is in one ~1200 line Rust file.
- The only Rust dependencies are the [Objc2](https://github.com/madsmtm/objc2) interop crates and the [lexopt](https://github.com/blyxxyz/lexopt) argument parser.
- There are no emoji anywhere in this repository.


## Install

Vibe is a single binary built with Rust.

Download [the latest binary built by GitHub actions](https://github.com/lynaghk/vibe/releases/tag/latest) and put it somewhere on your `$PATH`:

    curl -LO https://github.com/lynaghk/vibe/releases/download/latest/vibe-macos-arm64.zip
    unzip vibe-macos-arm64.zip
    mkdir -p ~/.local/bin
    mv vibe ~/.local/bin
    export PATH="$HOME/.local/bin:$PATH"

If you use [mise-en-place](https://mise.jdx.dev/):

    mise use github:lynaghk/vibe@latest

I'm not making formal releases or keeping a change log.
I recommend reading the commit history and pinning to a specific version.

You can also install via `cargo`:

    cargo install --locked --git https://github.com/lynaghk/vibe.git

If you don't have `cargo`, you need to install Rust:

    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


## Using Vibe


```
vibe [OPTIONS] [disk-image.raw]

Options

  --help                                                    Print this help message.
  --version                                                 Print the version (commit SHA).
  --no-default-mounts                                       Disable all default mounts.
  --mount host-path:guest-path[:read-only | :read-write]    Mount `host-path` inside VM at `guest-path`.
                                                            Defaults to read-write.
                                                            Errors if host-path does not exist.
  --cpus <count>                                            Number of virtual CPUs (default 2).
  --ram <megabytes>                                         RAM size in megabytes (default 2048).
  --script <path/to/script.sh>                              Run script in VM.
  --send <some-command>                                     Type `some-command` followed by newline into the VM.
  --expect <string> [timeout-seconds]                       Wait for `string` to appear in console output before executing next `--script` or `--send`.
                                                            If `string` does not appear within timeout (default 30 seconds), shutdown VM with error.
```

Invoking vibe without a disk image:

- shares the current directory with the VM
- shares package manager cache directories with the VM, so that packages are not re-downloaded
- shares the `~/.codex` directory with the VM, so you can use OpenAI's [codex](https://openai.com/codex/)
- shares the `~/.claude` directory with the VM, so you can use Anthropic's [claude](https://claude.com/product/claude-code)

The first time you run `vibe`, a Debian Linux image is downloaded to `~/.cache/vibe/`, configured with basic tools like gcc, [mise-en-place](https://mise.jdx.dev/), ripgrep, rust, etc., and saved as `default.raw`.
(See [provision.sh](/src/provision.sh) for details.)

Then when you run `vibe` in a project directory, it copies this default image to `.vibe/instance.raw`, boots it up, and attaches your terminal to this VM.

When you `exit` this shell, the VM is shutdown.
The disk state persists until you delete it.
There is no centralized registry of VMs --- if you want to delete a VM, just delete its disk image file.

## Other notes

- Apple Filesystem is copy-on-write, so instance images only use disk space when they diverge from the default image.
  You can use `du -h` to see how much space is actually consumed:

      $ /bin/ls -lah .vibe/instance.raw
      -rw-r--r--  1 dev  staff    10G Jan 25 20:41 .vibe/instance.raw

      $ du -h .vibe/instance.raw
      2.3G    .vibe/instance.raw

- MacOS only lets binaries signed with the `com.apple.security.virtualization` entitlement run virtual machines, so `vibe` checks itself on startup and, if necessary, signs itself using `codesign`. SeCuRiTy!

- Debian "nocloud" is used as a base image because it boots directly to a root prompt.
  The other images use [cloudinit](https://cloudinit.readthedocs.io/en/latest/), which I found much more complex:
  - Network requests are made during the boot process, and if you're offline they take several *minutes* to timeout before the login prompt is reached (thanks, `systemd-networkd-wait-online.service`).
  - Subsequent boots are much slower (at least, I couldn't easily figure out how to remove the associated cloud init machinery).


## Alternatives

Here's what I tried before writing this solution:

- [Sandboxtron](https://github.com/lynaghk/sandboxtron/) - My own little wrapper around Mac's `sandbox-exec`.
Turns out both Claude Code and Codex rely on this as well, and MacOS doesn't allow creating a sandbox from within a sandbox.
I considered writing my own sandboxing rules and running the agents `--yolo`, but didn't like the risk of configuration typos and/or Mac sandbox escapes (there are a lot --- I'm not an expert, but from [this HN discussion](https://news.ycombinator.com/item?id=42084588) I figured virtualization would be safer).

- [Lima](https://github.com/lima-vm/lima/), quick Linux VMs on Mac. I wanted to like this, ran into too many issues in first 30 minutes to trust it:
  - The recommended Debian image took 8 seconds to get to a login prompt, even after the VM was already running.
  - The CLI flags *mutate hidden state*. E.g., If you `limactl start --mount foo` and then later `limactl start --mount bar`, both `foo` and `bar` will be mounted.
  - Some capabilities are only available via yaml. E.g., the `--mount` CLI flag always mounts at the same path in the guest. If you want to mount at a different path, you have to do that via YAML.
  - There are many layers of inheritance/defaults, so even if you do write YAML, you can't see the full configuration.

- [Vagrant](https://developer.hashicorp.com/vagrant/) - I fondly remember using this back in the early 2010's, but based on this [2025 Reddit discussion](https://www.reddit.com/r/devops/comments/1axws75/vagrant_doesnt_support_mac_m1/) it seemed like running it on an ARM-based Mac was A Project and so I figured it'd be easier to roll my own thing.

- [Tart](https://tart.run/) - I found this via some positive HN comments, but unfortunately wasn't able to run the release binary from their GitHub because it's not signed.
They apparently hack around that when installing with homebrew, but I don't use homebrew either.
I tried cloning the repo and compiling myself, but the build failed with lots of language syntax errors despite the repo SHA is the same as one of their releases.
I assume this is a Swift problem and not Tart's, since this sort of mess happens most times when I try to build Swift. `¯\_(ツ)_/¯`

- [OrbStack](https://orbstack.dev/) - This looked nice, but seems mostly geared towards container stuff.
It runs a single VM, and I couldn't figure out how to have this VM run *without* my entire disk mounted inside of it.
I didn't want to run agents via containers, since containers aren't security boundaries.

- [Apple Container Framework](https://github.com/apple/container) - This looks technically promising, as it runs every container within a lightweight VM.
Unfortunately it requires MacOS 26 Tahoe, which wrecks [window resizing](https://news.ycombinator.com/item?id=46579864), adds [useless icons everywhere](https://news.ycombinator.com/item?id=46497712), and otherwise seems to be a mess.
Sorry excellent Apple programmers and hardware designers, I hope your management can reign in the haute couture folks before we all have to switch to Linux for professional computing.

- [QEMU](https://wiki.qemu.org/) - The first prototype of this app was [a single bash script](https://github.com/lynaghk/vibe/blob/1c82fd3b9fabf93abba2680fc856458e97a105cd/qemu.sh) wrapping `qemu`. This worked swimmingly, except for host/guest directory sharing, which ended up being a show-stopper. This is because QEMU doesn't support [virtiofs](https://virtio-fs.gitlab.io/) on Mac hosts, it only supports "9p", which is way slower ---  e.g., `mise use node@latest` takes > 10 minutes on 9p and 5 seconds on virtiofs.


## Roadmap / Collaboration

I wrote this software for myself, and I'm open to pull requests and otherwise collaborating on features that I'd personally use:

- resizing disk images
- forwarding ports from the host to a guest
- running `vibe` against a disk image that's already running should connect to the already-running VM
  - the VM shouldn't shutdown until all host terminals have logged out
- if not the above, at least a check and throw a nice error message when you try to start a VM that's already running
- a way to make faster-booting even more minimal Linux virtual machines
  - this should be bootstrappable on Mac; i.e., if the only way to make a small Linux image is with Linux-only tools, the entire process should still be runnable on MacOS via intermediate VMs
- propagate an exit code from within VM to the `vibe` command
- don't propagate user typing until all provided `--expect` and `--send` actions have completed
- CPU core / memory / networking configuration, possibly via flags or via extended attributes on the disk image file
- a `--plan` flag which pretty-prints a CLI invocation with all of the default arguments shown
  - to keep ourselves honest, we should use the same codepath for the actual execution (maybe we can `exec` into the generated command?)
  - Being fully "explicit" is tricky due to flag interactions.
    E.g., the friendly `--mount` would need to be decomposed into two flags: One that exposes the host directory in the guest's staging area at `/mnt/shared/` and another flag `--send 'mount --bind ...'`to bind this to the desired guest location.

I'm not sure about (but open to discussing proposals via GitHub issues):

- running VMs in the background
- supporting Linux hosts
- supporting guests beyond Debian Linux
- using SSH as a login mechanism; this would eliminate the current stdin/stdout-to-console plumbing (yay!) but require additional setup/configuration (boo!)
- making Claude Code work seamlessly
  - I tried the native installer but it sometimes fails during setup (see 6352d13), so I switched back to NPM via mise which is more reliable.
  - The `~/.claude` folder is shared in the VM by default, by apparently the `~/.claude.json` file is also required for auth credentials and session history.
    I'm not sure the best way to share a file between host and VM (virtioFS only works with folders).
    Also: Wild to me that Anthropic puts both a file and a folder in your home directory --- how rude!

I'm not interested in:

- anything related to Docker / containers / Kubernetes / distributed systems
