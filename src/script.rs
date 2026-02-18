use std::{fs, path::Path};

pub fn script_command_from_content(
    label: &str,
    script: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let marker = "VIBE_SCRIPT_EOF";
    let guest_dir = "/tmp/vibe-scripts";
    let guest_path = format!("{guest_dir}/{label}.sh");
    let command = format!(
        "mkdir -p {guest_dir}\ncat >{guest_path} <<'{marker}'\n{script}\n{marker}\nchmod +x {guest_path}\n{guest_path}"
    );
    if script.contains(marker) {
        return Err(
            format!("Script '{label}' contains marker '{marker}', cannot safely upload").into(),
        );
    }
    Ok(command)
}

pub fn script_command_from_path(
    path: &Path,
    index: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let script = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read script {}: {err}", path.display()))?;
    let label = format!("{}_{}", index, path.file_name().unwrap().display());
    script_command_from_content(&label, &script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_content() {
        let cmd = script_command_from_content("test", "echo hello").unwrap();
        assert!(cmd.contains("echo hello"));
        assert!(cmd.contains("VIBE_SCRIPT_EOF"));
    }

    #[test]
    fn rejects_marker_collision() {
        let err = script_command_from_content("test", "VIBE_SCRIPT_EOF").unwrap_err();
        assert!(err.to_string().contains("marker"));
    }

    #[test]
    fn makes_script_executable() {
        let cmd = script_command_from_content("myscript", "echo hi").unwrap();
        assert!(cmd.contains("chmod +x"));
    }
}
