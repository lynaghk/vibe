mod cli;
mod disk;
mod io;
mod script;
mod share;
mod vm;

use std::{env, fs, path::PathBuf};

use cli::{DEFAULT_RAM_MB, DEFAULT_CPU_COUNT, parse_cli};
use disk::{ensure_default_image, ensure_instance_disk};
use io::LoginAction::Send;
use share::{DirectoryShare, motd_login_action};
use vm::run_vm;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_cli()?;

    if args.version {
        println!("Vibe");
        println!("https://github.com/lynaghk/vibe/");
        println!("Git SHA: {}", env!("GIT_SHA"));
        std::process::exit(0);
    }

    if args.help {
        println!(
            "Vibe is a quick way to spin up a Linux virtual machine to sandbox LLM agents.

vibe [OPTIONS] [disk-image.raw]

Options

  --help                                                    Print this help message.
  --version                                                 Print the version (commit SHA).
  --no-default-mounts                                       Disable all default mounts, including .git and .vibe project subfolder masking.
  --mount host-path:guest-path[:read-only | :read-write]    Mount `host-path` inside VM at `guest-path`.
                                                            Defaults to read-write.
                                                            Errors if host-path does not exist.
  --cpus <count>                                            Number of virtual CPUs (default {DEFAULT_CPU_COUNT}).
  --ram <megabytes>                                         RAM size in megabytes (default {DEFAULT_RAM_MB}).
  --script <path/to/script.sh>                              Run script in VM.
  --send <some-command>                                     Type `some-command` followed by newline into the VM.
  --expect <string> [timeout-seconds]                       Wait for `string` to appear in console output before executing next `--script` or `--send`.
                                                            If `string` does not appear within timeout (default 30 seconds), shutdown VM with error.
"
        );
        std::process::exit(0);
    }

    #[cfg(target_os = "macos")]
    vm::ensure_signed();

    let project_root = env::current_dir()?;
    let project_name = project_root
        .file_name()
        .ok_or("Project directory has no name")?
        .to_string_lossy()
        .into_owned();

    let home = env::var("HOME").map(PathBuf::from)?;
    let cache_home = env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".cache"));
    let cache_dir = cache_home.join("vibe");
    let guest_mise_cache = cache_dir.join(".guest-mise-cache");
    let instance_dir = project_root.join(".vibe");

    let basename_compressed = disk::DEBIAN_COMPRESSED_DISK_URL.rsplit('/').next().unwrap();
    let base_compressed = cache_dir.join(basename_compressed);
    let base_raw = cache_dir.join(format!(
        "{}.raw",
        basename_compressed.trim_end_matches(".tar.xz")
    ));
    let default_raw = cache_dir.join("default.raw");
    let instance_raw = instance_dir.join("instance.raw");

    fs::create_dir_all(&cache_dir)?;
    fs::create_dir_all(&guest_mise_cache)?;

    let mise_directory_share =
        DirectoryShare::new(guest_mise_cache, "/root/.local/share/mise".into(), false)?;

    let disk_path = if let Some(path) = args.disk {
        if !path.exists() {
            return Err(format!("Disk image does not exist: {}", path.display()).into());
        }
        path
    } else {
        ensure_default_image(
            &base_raw,
            &base_compressed,
            &default_raw,
            std::slice::from_ref(&mise_directory_share),
        )?;
        ensure_instance_disk(&instance_raw, &default_raw)?;
        instance_raw
    };

    let mut login_actions = Vec::new();
    let mut directory_shares = Vec::new();

    if !args.no_default_mounts {
        login_actions.push(Send(format!("cd {project_name}")));

        for subfolder in [".git", ".vibe"] {
            if project_root.join(subfolder).exists() {
                login_actions.push(Send(format!("mount -t tmpfs tmpfs {}", subfolder)));
            }
        }

        directory_shares.push(
            DirectoryShare::new(
                project_root,
                PathBuf::from("/root/").join(&project_name),
                false,
            )
            .expect("Project directory must exist"),
        );

        directory_shares.push(mise_directory_share);

        for share in [
            DirectoryShare::new(home.join(".m2"),            "/root/.m2".into(),                false),
            DirectoryShare::new(home.join(".cargo/registry"),"/root/.cargo/registry".into(),    false),
            DirectoryShare::new(home.join(".codex"),         "/root/.codex".into(),             false),
            DirectoryShare::new(home.join(".claude"),        "/root/.claude".into(),            false),
            DirectoryShare::new(home.join(".gemini"),        "/root/.gemini".into(),            false),
        ]
        .into_iter()
        .flatten()
        {
            directory_shares.push(share);
        }
    }

    for spec in &args.mounts {
        directory_shares.push(DirectoryShare::from_mount_spec(spec)?);
    }

    if let Some(motd) = motd_login_action(&directory_shares) {
        login_actions.push(motd);
    }

    login_actions.extend(args.login_actions);

    run_vm(&disk_path, &login_actions, &directory_shares, args.cpu_count, args.ram_bytes)
}
