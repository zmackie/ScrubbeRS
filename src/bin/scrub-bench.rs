use scrubbers::Scrubber;
use std::time::Instant;

fn main() {
    let scrubber = Scrubber::new().expect("scrubber init");

    let mut payload = vec![b'a'; 64 * 1024 * 1024];
    let markers = [
        b"ghp_123456789012345678901234567890123456".as_slice(),
        b"AKIA1234567890ABCDEF".as_slice(),
        b"xoxb-123456789012-123456789012-abcdefghijklmnop".as_slice(),
    ];

    for (i, m) in markers.iter().enumerate() {
        let off = (i + 1) * 8 * 1024 * 1024;
        payload[off..off + m.len()].copy_from_slice(m);
    }

    // warmup
    let mut warm = payload.clone();
    scrubber.scrub_in_place(&mut warm);

    let runs = 10;
    let mut total = 0.0;
    for _ in 0..runs {
        let mut sample = payload.clone();
        let start = Instant::now();
        scrubber.scrub_in_place(&mut sample);
        total += start.elapsed().as_secs_f64();
    }

    let avg = total / runs as f64;
    let gib = payload.len() as f64 / (1024.0 * 1024.0 * 1024.0);
    let gib_s = gib / avg;

    println!(
        "processed={} MiB avg_time={:.4}s throughput={:.2} GiB/s",
        payload.len() / (1024 * 1024),
        avg,
        gib_s
    );
}
