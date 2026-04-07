use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempScrubFile {
    path: PathBuf,
}

impl TempScrubFile {
    fn new(contents: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("scrubbers-{}-{}.scrub", std::process::id(), unique));
        fs::write(&path, contents).expect("failed to write temp .scrub file");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempScrubFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn run_scrubbers(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scrubbers"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to launch scrubbers binary");

    child
        .stdin
        .as_mut()
        .expect("stdin should be piped")
        .write_all(input)
        .expect("failed to write test input");

    child
        .wait_with_output()
        .expect("failed to wait for scrubbers")
}

#[test]
fn cli_stream_lines_redacts_builtin_secret() {
    let input = b"safe\nprefix ghp_123456789012345678901234567890123456 suffix\n";
    let output = run_scrubbers(&["--stream-lines"], input);

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        output.stdout,
        b"safe\nprefix **************************************** suffix\n"
    );
}

#[test]
fn cli_stream_lines_applies_custom_scrub_file() {
    let scrub_file = TempScrubFile::new("foo-secret\n");
    let scrub_file_arg = scrub_file
        .path()
        .to_str()
        .expect("path should be valid utf-8");

    let output = run_scrubbers(
        &["--stream-lines", "--scrub-file", scrub_file_arg],
        b"hello foo-secret world\n",
    );

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.stdout, b"hello ********** world\n");
}
