use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use crate::{
    cli::{DEFAULT_CPU_COUNT, DEFAULT_RAM_BYTES},
    io::LoginAction::Send,
    script::script_command_from_content,
    share::DirectoryShare,
    vm::run_vm,
};

pub(crate) const BYTES_PER_MB: u64 = 1024 * 1024;

const PROVISION_SCRIPT: &str = include_str!("provision.sh");

// ── Platform-specific disk image constants ────────────────────────────────────

#[cfg(target_os = "macos")]
pub(crate) const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
#[cfg(target_os = "macos")]
pub(crate) const DEBIAN_COMPRESSED_SHA: &str = "6ab9be9e6834adc975268367f2f0235251671184345c34ee13031749fdfbf66fe4c3aafd949a2d98550426090e9ac645e79009c51eb0eefc984c15786570bb38";
#[cfg(target_os = "macos")]
pub(crate) const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 280_901_576;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-amd64-20260112-2355.tar.xz";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const DEBIAN_COMPRESSED_SHA: &str = "765890bb31a071be829a64d086923447476b94b9c02faecff80f787a7e261f2088449f94ce362e5cb752901b188c443a284cb91bc98991fdcf375beca4a54eb9";
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 285_000_000;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const DEBIAN_COMPRESSED_DISK_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20260112-2355/debian-13-nocloud-arm64-20260112-2355.tar.xz";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const DEBIAN_COMPRESSED_SHA: &str = "6ab9be9e6834adc975268367f2f0235251671184345c34ee13031749fdfbf66fe4c3aafd949a2d98550426090e9ac645e79009c51eb0eefc984c15786570bb38";
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const DEBIAN_COMPRESSED_SIZE_BYTES: u64 = 280_901_576;

// ── Public API ────────────────────────────────────────────────────────────────

pub fn verify_sha512(file_path: &Path, expected_sha: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    {
        let input = format!("{}  {}\n", expected_sha, file_path.display());
        let mut child = Command::new("/usr/bin/shasum")
            .args(["--algorithm", "512", "--check"])
            .stdin(Stdio::piped())
            .spawn()
            .expect("failed to spawn shasum");
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
        if !child.wait()?.success() {
            return Err(format!("SHA validation failed for {}", file_path.display()).into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let input = format!("{}  {}\n", expected_sha, file_path.display());
        let mut child = Command::new("sha512sum")
            .args(["--check"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn sha512sum: {e}"))?;
        child.stdin.take().unwrap().write_all(input.as_bytes())?;
        if !child.wait()?.success() {
            return Err(format!("SHA validation failed for {}", file_path.display()).into());
        }
    }
    Ok(())
}

pub fn ensure_base_image(
    base_raw: &Path,
    base_compressed: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if base_raw.exists() {
        return Ok(());
    }

    if !base_compressed.exists()
        || fs::metadata(base_compressed).map(|m| m.len())? < DEBIAN_COMPRESSED_SIZE_BYTES
    {
        println!("Downloading base image...");
        let status = Command::new("curl")
            .args([
                "--continue-at", "-",
                "--compressed",
                "--location",
                "--fail",
                "-o", &base_compressed.to_string_lossy(),
                DEBIAN_COMPRESSED_DISK_URL,
            ])
            .status()?;
        if !status.success() {
            return Err("Failed to download base image".into());
        }
    }

    verify_sha512(base_compressed, DEBIAN_COMPRESSED_SHA)?;

    println!("Decompressing base image...");
    let status = Command::new("tar")
        .args(["-xOf", &base_compressed.to_string_lossy(), "disk.raw"])
        .stdout(fs::File::create(base_raw)?)
        .status()?;
    if !status.success() {
        return Err("Failed to decompress base image".into());
    }

    Ok(())
}

pub fn ensure_default_image(
    base_raw: &Path,
    base_compressed: &Path,
    default_raw: &Path,
    directory_shares: &[DirectoryShare],
) -> Result<(), Box<dyn std::error::Error>> {
    if default_raw.exists() {
        return Ok(());
    }

    ensure_base_image(base_raw, base_compressed)?;

    println!("Configuring base image...");
    fs::copy(base_raw, default_raw)?;

    fs::OpenOptions::new()
        .write(true)
        .open(default_raw)?
        .set_len(20 * 1024 * BYTES_PER_MB)?; // 20 GiB

    let provision_command = script_command_from_content("provision.sh", PROVISION_SCRIPT)?;
    run_vm(
        default_raw,
        &[Send(provision_command)],
        directory_shares,
        DEFAULT_CPU_COUNT,
        DEFAULT_RAM_BYTES,
    )?;

    Ok(())
}

pub fn ensure_instance_disk(
    instance_raw: &Path,
    template_raw: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if instance_raw.exists() {
        return Ok(());
    }
    println!("Creating instance disk from {}...", template_raw.display());
    fs::create_dir_all(instance_raw.parent().unwrap())?;
    fs::copy(template_raw, instance_raw)?;
    Ok(())
}
