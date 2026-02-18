use std::{ffi::OsString, path::PathBuf, time::Duration};

use lexopt::prelude::*;

use crate::io::LoginAction;

pub(crate) const DEFAULT_CPU_COUNT: usize = 2;
pub(crate) const DEFAULT_RAM_MB: u64 = 2048;
pub(crate) const DEFAULT_RAM_BYTES: u64 = DEFAULT_RAM_MB * 1024 * 1024;
const DEFAULT_EXPECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct CliArgs {
    pub disk: Option<PathBuf>,
    pub version: bool,
    pub help: bool,
    pub no_default_mounts: bool,
    pub mounts: Vec<String>,
    pub login_actions: Vec<LoginAction>,
    pub cpu_count: usize,
    pub ram_bytes: u64,
}

pub fn parse_cli() -> Result<CliArgs, Box<dyn std::error::Error>> {
    fn os_to_string(value: OsString, flag: &str) -> Result<String, Box<dyn std::error::Error>> {
        value
            .into_string()
            .map_err(|_| format!("{flag} expects valid UTF-8").into())
    }

    let mut parser = lexopt::Parser::from_env();
    let mut disk = None;
    let mut version = false;
    let mut help = false;
    let mut no_default_mounts = false;
    let mut mounts = Vec::new();
    let mut login_actions = Vec::new();
    let mut script_index = 0;
    let mut cpu_count = DEFAULT_CPU_COUNT;
    let mut ram_bytes = DEFAULT_RAM_BYTES;

    while let Some(arg) = parser.next()? {
        match arg {
            Long("version") => version = true,
            Long("help") | Short('h') => help = true,
            Long("no-default-mounts") => no_default_mounts = true,
            Long("cpus") => {
                let value = os_to_string(parser.value()?, "--cpus")?.parse()?;
                if value == 0 { return Err("--cpus must be >= 1".into()); }
                cpu_count = value;
            }
            Long("ram") => {
                let value: u64 = os_to_string(parser.value()?, "--ram")?.parse()?;
                if value == 0 { return Err("--ram must be >= 1".into()); }
                ram_bytes = value * 1024 * 1024;
            }
            Long("mount") => {
                mounts.push(os_to_string(parser.value()?, "--mount")?);
            }
            Long("script") => {
                login_actions.push(LoginAction::Script {
                    path: os_to_string(parser.value()?, "--script")?.into(),
                    index: script_index,
                });
                script_index += 1;
            }
            Long("send") => {
                login_actions.push(LoginAction::Send(os_to_string(parser.value()?, "--send")?));
            }
            Long("expect") => {
                let text = os_to_string(parser.value()?, "--expect")?;
                let timeout = match parser.optional_value() {
                    Some(value) => {
                        Duration::from_secs(os_to_string(value, "--expect")?.parse()?)
                    }
                    None => DEFAULT_EXPECT_TIMEOUT,
                };
                login_actions.push(LoginAction::Expect { text, timeout });
            }
            Value(value) => {
                if disk.is_some() {
                    return Err("Only one disk path may be provided".into());
                }
                disk = Some(PathBuf::from(value));
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    Ok(CliArgs { disk, version, help, no_default_mounts, mounts, login_actions, cpu_count, ram_bytes })
}
