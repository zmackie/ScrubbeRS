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

fn benchmark_throughput(c: &mut Criterion) {
    let payload = build_payload();
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
}

criterion_group!(benches, benchmark_throughput);
criterion_main!(benches);
