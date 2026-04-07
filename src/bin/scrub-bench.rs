use scrubbers::Scrubber;
use std::io::Cursor;
use std::time::Instant;

const PAYLOAD_SIZE: usize = 64 * 1024 * 1024;

fn build_in_place_payload() -> Vec<u8> {
    let mut payload = vec![b'a'; PAYLOAD_SIZE];
    let markers = [
        b"ghp_123456789012345678901234567890123456".as_slice(),
        b"AKIA1234567890ABCDEF".as_slice(),
        b"xoxb-123456789012-123456789012-abcdefghijklmnop".as_slice(),
    ];

    for (i, m) in markers.iter().enumerate() {
        let off = (i + 1) * 8 * 1024 * 1024;
        payload[off..off + m.len()].copy_from_slice(m);
    }

    payload
}

fn build_line_payload() -> Vec<u8> {
    let safe_line = b"INFO request_id=req-123 status=200 component=api message=all-good\n";
    let secret_lines = [
        b"INFO source=github token=ghp_123456789012345678901234567890123456 user=fixture\n"
            .as_slice(),
        b"INFO source=aws access_key=AKIA1234567890ABCDEF account=fixture\n".as_slice(),
        b"INFO source=slack token=xoxb-123456789012-123456789012-abcdefghijklmnop channel=alerts\n"
            .as_slice(),
    ];

    let mut payload = Vec::with_capacity(PAYLOAD_SIZE);
    let mut line_idx = 0usize;
    while payload.len() + safe_line.len() <= PAYLOAD_SIZE {
        let line = if line_idx % 2048 == 0 {
            secret_lines[(line_idx / 2048) % secret_lines.len()]
        } else {
            safe_line
        };
        if payload.len() + line.len() > PAYLOAD_SIZE {
            break;
        }
        payload.extend_from_slice(line);
        line_idx += 1;
    }

    if payload.len() < PAYLOAD_SIZE {
        payload.extend(std::iter::repeat_n(b'a', PAYLOAD_SIZE - payload.len()));
    }

    payload
}

fn print_result(name: &str, payload_size: usize, avg_seconds: f64) {
    let gib = payload_size as f64 / (1024.0 * 1024.0 * 1024.0);
    let gib_s = gib / avg_seconds;
    println!(
        "mode={} processed={} MiB avg_time={:.4}s throughput={:.2} GiB/s",
        name,
        payload_size / (1024 * 1024),
        avg_seconds,
        gib_s
    );
}

fn main() {
    let scrubber = Scrubber::new().expect("scrubber init");
    let payload = build_in_place_payload();
    let line_payload = build_line_payload();

    // warmup
    let mut warm = payload.clone();
    scrubber.scrub_in_place(&mut warm);
    let mut warm_lines = Vec::with_capacity(line_payload.len());
    scrubber
        .scrub_lines(Cursor::new(line_payload.as_slice()), &mut warm_lines)
        .expect("streaming warmup");

    let runs = 10;
    let mut total_in_place = 0.0;
    for _ in 0..runs {
        let mut sample = payload.clone();
        let start = Instant::now();
        scrubber.scrub_in_place(&mut sample);
        total_in_place += start.elapsed().as_secs_f64();
    }

    let mut total_stream_lines = 0.0;
    for _ in 0..runs {
        let mut output = Vec::with_capacity(line_payload.len());
        let start = Instant::now();
        scrubber
            .scrub_lines(Cursor::new(line_payload.as_slice()), &mut output)
            .expect("streaming run");
        total_stream_lines += start.elapsed().as_secs_f64();
    }

    print_result("in_place", payload.len(), total_in_place / runs as f64);
    print_result(
        "stream_lines",
        line_payload.len(),
        total_stream_lines / runs as f64,
    );
}
