use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scrubbers::Scrubber;
use std::io::{self, Cursor, Write};
use std::time::{Duration, Instant};

const PAYLOAD_SIZE: usize = 64 * 1024 * 1024;

struct SliceWriter<'a> {
    buffer: &'a mut [u8],
    written: usize,
}

impl<'a> SliceWriter<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, written: 0 }
    }
}

impl Write for SliceWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let end = self.written + buf.len();
        self.buffer[self.written..end].copy_from_slice(buf);
        self.written = end;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn build_payload() -> Vec<u8> {
    let mut payload = vec![b'a'; PAYLOAD_SIZE];
    let markers = [
        b"ghp_123456789012345678901234567890123456".as_slice(),
        b"AKIA1234567890ABCDEF".as_slice(),
        b"xoxb-123456789012-123456789012-abcdefghijklmnop".as_slice(),
    ];

    for (i, marker) in markers.iter().enumerate() {
        let offset = (i + 1) * 8 * 1024 * 1024;
        payload[offset..offset + marker.len()].copy_from_slice(marker);
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

fn benchmark_throughput(c: &mut Criterion) {
    let payload = build_payload();
    let line_payload = build_line_payload();
    let scrubber = Scrubber::new().expect("scrubber init");

    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.sample_size(20);

    group.bench_function(BenchmarkId::new("pass_through", "memcpy"), |b| {
        let mut sample = vec![0_u8; payload.len()];
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                sample.copy_from_slice(&payload);
                total += start.elapsed();
                black_box(&sample);
            }
            total
        });
    });

    group.bench_function(BenchmarkId::new("pass_through", "io_copy_to_buffer"), |b| {
        let mut sample = vec![0_u8; payload.len()];
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut reader = Cursor::new(payload.as_slice());
                let mut writer = SliceWriter::new(&mut sample);
                let start = Instant::now();
                io::copy(&mut reader, &mut writer).expect("copy to buffer");
                total += start.elapsed();
                black_box(&sample);
            }
            total
        });
    });

    group.bench_function(BenchmarkId::new("scrubber", "in_place"), |b| {
        let mut sample = payload.clone();
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                sample.copy_from_slice(&payload);
                let start = Instant::now();
                scrubber.scrub_in_place(&mut sample);
                total += start.elapsed();
                black_box(&sample);
            }
            total
        });
    });

    group.finish();

    let mut streaming_group = c.benchmark_group("throughput_streaming");
    streaming_group.throughput(Throughput::Bytes(line_payload.len() as u64));
    streaming_group.sample_size(10);
    streaming_group.measurement_time(Duration::from_secs(12));

    streaming_group.bench_function(BenchmarkId::new("scrubber", "stream_lines"), |b| {
        let mut sample = vec![0_u8; line_payload.len()];
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut reader = Cursor::new(line_payload.as_slice());
                let mut writer = SliceWriter::new(&mut sample);
                let start = Instant::now();
                scrubber
                    .scrub_lines(&mut reader, &mut writer)
                    .expect("line scrub to buffer");
                total += start.elapsed();
                black_box(&sample);
            }
            total
        });
    });

    streaming_group.finish();
}

criterion_group!(benches, benchmark_throughput);
criterion_main!(benches);
