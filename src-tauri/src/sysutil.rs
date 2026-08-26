//! Small helpers for defensively invoking Windows command-line tools.
//!
//! Every check-agent that shells out goes through [`run_command`], which
//! never builds a command line by string concatenation from untrusted
//! input - arguments are always passed as a fixed, hard-coded argv array -
//! and always returns a `Result` instead of panicking on a missing binary,
//! non-zero exit, or invalid UTF-8.

use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

// CREATE_NO_WINDOW: don't flash a console window when we shell out from the
// GUI app.
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Runs `program` with a fixed argv, waits for completion, and returns
/// stdout decoded as (lossy) UTF-8. Returns `Err` with a human-readable
/// message on any failure (binary missing, launch failure, non-zero exit
/// with no usable stdout).
pub fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let output = cmd
        .output()
        .map_err(|e| format!("failed to launch `{program}`: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    if !output.status.success() && stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(format!(
            "`{program}` exited with {:?}: {}",
            output.status.code(),
            stderr.trim()
        ));
    }

    Ok(stdout)
}
