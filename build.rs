use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn run(cmd: &mut Command) {
    let status = cmd
        .status()
        .unwrap_or_else(|_| panic!("failed to run {cmd:?}"));
    assert!(status.success(), "command failed: {cmd:?}");
}

fn write_if_changed(path: &Path, content: &str) {
    let existing = fs::read_to_string(path).ok();
    if existing.as_deref() != Some(content) {
        fs::write(path, content).unwrap_or_else(|_| panic!("failed to write {}", path.display()));
    }
}

fn build_vmnet_helper(manifest_dir: &Path, out_dir: &Path) -> PathBuf {
    let vmnet_dir = manifest_dir.join("vendor/vmnet-helper");
    let build_dir = out_dir.join("vmnet-helper-build");
    fs::create_dir_all(&build_dir).expect("create vmnet-helper build dir");

    let config_h = build_dir.join("config.h");
    let version_h = build_dir.join("version.h");
    let vmnet_helper_path = build_dir.join("vmnet-helper");

    let config_template =
        fs::read_to_string(vmnet_dir.join("config.h.in")).expect("read config.h.in");
    write_if_changed(
        &config_h,
        &config_template.replace("@PREFIX@", "/opt/vmnet-helper"),
    );

    let sha = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&vmnet_dir)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap();

    // Use only the commit hash in the generated header so the helper build does
    // not depend on tag state in the local clone.
    write_if_changed(
        &version_h,
        &format!("#define GIT_VERSION \"{sha}\"\n#define GIT_COMMIT  \"{sha}\"\n"),
    );

    let mut clang = Command::new("clang");
    clang
        .current_dir(&vmnet_dir)
        .args(["-target", "arm64-apple-macos14.0", "-arch", "arm64"])
        .arg("-std=gnu99")
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-fPIE")
        .arg("-I")
        .arg(&build_dir)
        .arg("-I")
        .arg(&vmnet_dir)
        .arg("-I")
        .arg(vmnet_dir.join("vmnet-broker"));

    clang
        .arg("helper.c")
        .arg("options.c")
        .arg("vmnet-broker/client.c")
        .args(["-framework", "vmnet"])
        .args(["-framework", "CoreFoundation"])
        .arg("-o")
        .arg(&vmnet_helper_path);

    run(&mut clang);

    vmnet_helper_path
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let host = env::var("HOST").unwrap_or_default();
    let target = env::var("TARGET").unwrap();

    // Build the vmnet-helper. Logic extracted from /vendor/vmnet-helper/build.sh
    // Limit this to Apple hosts; on others, create a stub file so we can still run `cargo check` (e.g., from within Vibe =D)
    if host.contains("apple-darwin") && target == "aarch64-apple-darwin" {
        let vmnet_dir = manifest_dir.join("vendor/vmnet-helper");
        let vmnet_helper_path = build_vmnet_helper(&manifest_dir, &out_dir);

        run(Command::new("codesign")
            .args(["--force", "--verbose", "--entitlements"])
            .arg(vmnet_dir.join("entitlements.plist"))
            .args(["--sign", "-"])
            .arg(&vmnet_helper_path));

        println!(
            "cargo:rustc-env=BUNDLED_VMNET_HELPER_PATH={}",
            vmnet_helper_path.display()
        );

        for entry in fs::read_dir(&vmnet_dir).expect("read vendor dir").flatten() {
            let path = entry.path();
            if let Some("c" | "h" | "plist" | "ini") = path.extension().and_then(|e| e.to_str()) {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
        println!(
            "cargo:rerun-if-changed={}",
            vmnet_dir.join("vmnet-broker/client.c").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            vmnet_dir.join("vmnet-broker/vmnet-broker.h").display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            vmnet_dir.join("config.h.in").display()
        );
        println!("cargo:rerun-if-env-changed=TARGET");
    } else {
        let stub_path = out_dir.join("stub-vmnet-helper");
        fs::write(&stub_path, []).expect("write stub vmnet-helper");
        println!(
            "cargo:rustc-env=BUNDLED_VMNET_HELPER_PATH={}",
            stub_path.display()
        );
    }

    // Expose GIT_SHA and BUILD_DATE vars so Vibe can embed them in its version info
    {
        let sha = Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        let build_date = Command::new("date")
            .args(["-u", "+%F"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into());

        println!("cargo:rustc-env=GIT_SHA={sha}");
        println!("cargo:rustc-env=BUILD_DATE={build_date}");
        println!("cargo:rerun-if-changed=.git/HEAD");
    }
}
