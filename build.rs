use std::process::Command;

fn main() {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());

    println!("cargo:rustc-env=GIT_SHA={sha}");
    println!("cargo:rerun-if-changed=.git/HEAD");

    // Also watch the actual ref so the SHA updates on each commit,
    // not just when switching branches.
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(refpath) = head.strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed=.git/{}", refpath.trim());
        }
    }
}
