use std::path::PathBuf;

use crate::io::LoginAction;

#[cfg(target_os = "macos")]
pub(crate) const SHARED_DIRECTORIES_TAG: &str = "shared";

#[derive(Clone)]
pub struct DirectoryShare {
    pub host: PathBuf,
    pub guest: PathBuf,
    pub read_only: bool,
}

impl DirectoryShare {
    pub fn new(
        host: PathBuf,
        mut guest: PathBuf,
        read_only: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !host.exists() {
            return Err(format!("Host path does not exist: {}", host.display()).into());
        }
        if !guest.is_absolute() {
            guest = PathBuf::from("/root").join(guest);
        }
        Ok(Self { host, guest, read_only })
    }

    pub fn from_mount_spec(spec: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!("Invalid mount spec: {spec}").into());
        }
        let host = PathBuf::from(parts[0]);
        let guest = PathBuf::from(parts[1]);
        let read_only = if parts.len() == 3 {
            match parts[2] {
                "read-only" => true,
                "read-write" => false,
                _ => {
                    return Err(format!(
                        "Invalid mount mode '{}'; expected read-only or read-write",
                        parts[2]
                    )
                    .into());
                }
            }
        } else {
            false
        };
        Self::new(host, guest, read_only)
    }

    pub fn tag(&self) -> String {
        let path_str = self.host.to_string_lossy();
        let hash = path_str
            .bytes()
            .fold(5381u64, |h, b| h.wrapping_mul(33).wrapping_add(b as u64));
        let base_name = self
            .host
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or("share".into());
        format!("{}_{:016x}", base_name, hash)
    }
}

pub fn motd_login_action(directory_shares: &[DirectoryShare]) -> Option<LoginAction> {
    use LoginAction::Send;

    if directory_shares.is_empty() {
        return Some(Send("clear".into()));
    }

    let host_header = "Host";
    let guest_header = "Guest";
    let mode_header = "Mode";
    let mut host_width = host_header.len();
    let mut guest_width = guest_header.len();
    let mut mode_width = mode_header.len();
    let mut rows = Vec::with_capacity(directory_shares.len());

    for share in directory_shares {
        let host = share.host.to_string_lossy().into_owned();
        let guest = share.guest.to_string_lossy().into_owned();
        let mode = if share.read_only { "read-only" } else { "read-write" }.to_string();
        host_width = host_width.max(host.len());
        guest_width = guest_width.max(guest.len());
        mode_width = mode_width.max(mode.len());
        rows.push((host, guest, mode));
    }

    let mut output = String::new();
    output.push_str(
        "
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░
   ░▒▓██▓▒░  ░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░

",
    );
    output.push_str(&format!(
        "{host_header:<host_width$}  {guest_header:<guest_width$}  {mode_header}\n",
        host_width = host_width
    ));
    output.push_str(&format!(
        "{:-<host_width$}  {:-<guest_width$}  {:-<mode_width$}\n",
        "", "", "",
        host_width = host_width, guest_width = guest_width, mode_width = mode_width
    ));
    for (host, guest, mode) in rows {
        output.push_str(&format!("{host:<host_width$}  {guest:<guest_width$}  {mode}\n"));
    }

    let command = format!("clear && cat <<'VIBE_MOTD'\n{output}\nVIBE_MOTD");
    Some(Send(command))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_spec_two_parts() {
        let s = DirectoryShare::from_mount_spec("/tmp:/root/tmp").unwrap();
        assert_eq!(s.host, std::path::PathBuf::from("/tmp"));
        assert_eq!(s.guest, std::path::PathBuf::from("/root/tmp"));
        assert!(!s.read_only);
    }

    #[test]
    fn mount_spec_read_only() {
        let s = DirectoryShare::from_mount_spec("/tmp:/root/tmp:read-only").unwrap();
        assert!(s.read_only);
    }

    #[test]
    fn mount_spec_read_write_explicit() {
        let s = DirectoryShare::from_mount_spec("/tmp:/root/tmp:read-write").unwrap();
        assert!(!s.read_only);
    }

    #[test]
    fn mount_spec_relative_guest_becomes_absolute() {
        let s = DirectoryShare::from_mount_spec("/tmp:myproject").unwrap();
        assert_eq!(s.guest, std::path::PathBuf::from("/root/myproject"));
    }

    #[test]
    fn mount_spec_too_few_parts() {
        assert!(DirectoryShare::from_mount_spec("/tmp").is_err());
    }

    #[test]
    fn mount_spec_too_many_parts() {
        assert!(DirectoryShare::from_mount_spec("/tmp:/root/tmp:read-only:extra").is_err());
    }

    #[test]
    fn mount_spec_invalid_mode() {
        assert!(DirectoryShare::from_mount_spec("/tmp:/root/tmp:rw").is_err());
    }

    #[test]
    fn mount_spec_nonexistent_host_errors() {
        assert!(DirectoryShare::from_mount_spec("/nonexistent_vibe_test_path:/root/x").is_err());
    }

    #[test]
    fn tag_is_deterministic() {
        let a = DirectoryShare::from_mount_spec("/tmp:/root/tmp").unwrap();
        let b = DirectoryShare::from_mount_spec("/tmp:/root/tmp").unwrap();
        assert_eq!(a.tag(), b.tag());
    }

    #[test]
    fn tag_differs_for_different_host_paths() {
        let a = DirectoryShare::from_mount_spec("/tmp:/root/a").unwrap();
        let b = DirectoryShare::from_mount_spec("/var/tmp:/root/b").unwrap();
        assert_ne!(a.tag(), b.tag());
    }

    #[test]
    fn tag_contains_directory_basename() {
        let s = DirectoryShare::from_mount_spec("/tmp:/root/tmp").unwrap();
        assert!(s.tag().starts_with("tmp_"));
    }

    #[test]
    fn motd_clears_with_no_shares() {
        let LoginAction::Send(cmd) = motd_login_action(&[]).unwrap() else {
            panic!("expected Send")
        };
        assert_eq!(cmd, "clear");
    }

    #[test]
    fn motd_contains_share_paths() {
        let s = DirectoryShare::from_mount_spec("/tmp:/root/myproject").unwrap();
        let LoginAction::Send(cmd) = motd_login_action(&[s]).unwrap() else {
            panic!("expected Send")
        };
        assert!(cmd.contains("/tmp"));
        assert!(cmd.contains("/root/myproject"));
        assert!(cmd.contains("read-write"));
    }

    #[test]
    fn motd_marks_read_only_shares() {
        let s = DirectoryShare::from_mount_spec("/tmp:/root/ro:read-only").unwrap();
        let LoginAction::Send(cmd) = motd_login_action(&[s]).unwrap() else {
            panic!("expected Send")
        };
        assert!(cmd.contains("read-only"));
    }
}
