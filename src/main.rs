use anyhow::Context;
use clap::Parser;
use scrubbers::{default_signatures, parse_scrub_file, Scrubber};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "scrubbers", about = "Ultra-fast stdin/stdout secret scrubber")]
struct Args {
    /// Optional custom signature file (.scrub)
    #[arg(short, long)]
    scrub_file: Option<PathBuf>,

    /// Replacement byte (defaults to '*')
    #[arg(long, default_value = "*")]
    mask: String,

    /// Process stdin incrementally by newline-delimited records.
    #[arg(long)]
    stream_lines: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mask_byte = args.mask.as_bytes().first().copied().unwrap_or(b'*');

    let mut signatures = default_signatures();
    if let Some(path) = args.scrub_file.as_deref() {
        signatures.extend(parse_scrub_file(path).context("parsing custom .scrub file")?);
    }

    let scrubber = Scrubber::with_signatures(signatures, mask_byte)?;

    if args.stream_lines {
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        scrubber.scrub_lines(BufReader::new(stdin.lock()), stdout.lock())?;
    } else {
        let mut buf = Vec::with_capacity(64 * 1024);
        std::io::stdin().read_to_end(&mut buf)?;
        scrubber.scrub_in_place(&mut buf);
        std::io::stdout().write_all(&buf)?;
    }
    Ok(())
}
