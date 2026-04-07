use std::io::Write;
use std::process::{Command, Output, Stdio};

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
fn cli_starts_with_empty_input() {
    let output = run_scrubbers(&[], b"");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn cli_leaves_plain_text_unchanged() {
    let output = run_scrubbers(&[], b"test");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(output.stdout, b"test");
}
