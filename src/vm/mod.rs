#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
pub use macos::{ensure_signed, run_vm};
#[cfg(target_os = "linux")]
pub use linux::run_vm;
