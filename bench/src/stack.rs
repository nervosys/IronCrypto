//! Peak stack use per operation, measured by painting.
//!
//! A thread with a large stack fills a megabyte below its current frame with a
//! known byte, runs one operation through a call that cannot be inlined, and
//! then scans upward from the bottom of the painted region for the first byte
//! that changed. The distance from there to the frame the operation was called
//! from is its high-water mark, to the byte. An empty operation is measured the
//! same way and subtracted, so the figure excludes the harness's own call.
//!
//! This is a lower bound on what a caller must provide, in the same sense the
//! "smallest stack that completes" probe is: a byte written with the paint
//! value itself is invisible. The probability of that being the deepest write
//! is small but not zero, so treat the figures as accurate to a few bytes.
//!
//! Probing for the smallest thread stack that completes is the other method,
//! and on Linux it is accurate to a 4 KiB page. On Windows a thread's stack is
//! reserved in 64 KiB units, so it is not usable there; painting is
//! byte-granular on both.
//!
//! The operations are the library's public entry points with fixed inputs.
//! Each is also timed, so a change to stack use can be read beside what it
//! cost: the mean over a batch, best of several batches.

use std::hint::black_box;
use std::time::Instant;

/// How much of the stack is painted. Larger than any operation measured here.
const PAINT: usize = 1 << 20;
const BYTE: u8 = 0xA5;

#[inline(never)]
fn paint() {
    let mut buf = [BYTE; PAINT];
    black_box(&mut buf);
}

#[inline(never)]
fn here() -> usize {
    let marker = 0u8;
    black_box(&marker) as *const u8 as usize
}

#[inline(never)]
fn call(f: &mut dyn FnMut()) {
    f();
}

#[inline(never)]
fn high_water(f: &mut dyn FnMut()) -> usize {
    let top = here();
    paint();
    call(f);
    // `paint` and `here` are called from the same depth, so the painted buffer
    // ends at about `top` and starts about `PAINT` below it. Scanning starts a
    // page above that start, which keeps it inside the paint whatever the
    // exact frame layout; it caps a measurement at `PAINT` less a page.
    let bottom = top - PAINT + 4096;
    let mut deepest = top;
    for addr in bottom..top {
        // SAFETY: the range lies within this thread's stack, below the current
        // frame, and was committed by `paint`, which wrote every byte of it.
        let byte = unsafe { core::ptr::read_volatile(addr as *const u8) };
        if byte != BYTE {
            deepest = addr;
            break;
        }
    }
    top - deepest
}

fn measure(f: &mut dyn FnMut()) -> usize {
    let baseline = high_water(&mut || {});
    high_water(f).saturating_sub(baseline)
}

/// Mean microseconds per call over a batch, best of five batches.
fn time(f: &mut dyn FnMut(), per_batch: u32) -> f64 {
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..per_batch {
            f();
        }
        let us = start.elapsed().as_secs_f64() * 1e6 / per_batch as f64;
        best = best.min(us);
    }
    best
}

fn row(name: &str, f: &mut dyn FnMut(), per_batch: u32) {
    let bytes = measure(f);
    let us = time(f, per_batch);
    println!(
        "{name:<28} {bytes:>8} B  {kib:>7.1} KiB  {us:>10.1} us",
        kib = bytes as f64 / 1024.0
    );
}

macro_rules! mldsa_rows {
    ($name:literal, $m:path) => {{
        use $m as m;
        let xi = [0x5au8; 32];
        let mut pk = [0u8; m::PUBLIC_KEY_LEN];
        let mut sk = [0u8; m::SECRET_KEY_LEN];
        assert!(m::keygen(&xi, &mut pk, &mut sk));
        let mut sig = [0u8; m::SIGNATURE_LEN];
        assert!(m::sign(&sk, b"stack", b"", &[7u8; 32], &mut sig));
        assert!(m::verify(&pk, b"stack", b"", &sig));

        // Signing time depends on how many attempts a message needs, which
        // varies by several times between messages. Keygen includes a signature
        // for its consistency test, so it varies too. Both cycle through 64
        // inputs, and a batch is 64 calls, so every batch times the same set.
        let mut n = 0u8;
        row(
            concat!($name, " keygen"),
            &mut || {
                n = n.wrapping_add(1) % 64;
                let mut pk = [0u8; m::PUBLIC_KEY_LEN];
                let mut sk = [0u8; m::SECRET_KEY_LEN];
                let mut seed = xi;
                seed[0] = n;
                assert!(m::keygen(black_box(&seed), &mut pk, &mut sk));
                black_box((&pk, &sk));
            },
            64,
        );
        row(
            concat!($name, " sign"),
            &mut || {
                n = n.wrapping_add(1) % 64;
                let mut out = [0u8; m::SIGNATURE_LEN];
                assert!(m::sign(black_box(&sk), &[n], b"", &[7u8; 32], &mut out));
                black_box(&out);
            },
            64,
        );
        row(
            concat!($name, " verify"),
            &mut || {
                assert!(m::verify(black_box(&pk), b"stack", b"", black_box(&sig)));
            },
            128,
        );
    }};
}

pub fn run() {
    let which: Vec<String> = std::env::args().skip(2).collect();
    let wants = move |group: &str| which.is_empty() || which.iter().any(|w| w == group);
    let worker = std::thread::Builder::new()
        .stack_size(16 << 20)
        .spawn(move || {
            println!(
                "{:<28} {:>10}  {:>11}  {:>13}",
                "operation", "peak", "", "time"
            );
            if wants("mldsa") {
                mldsa_rows!("ML-DSA-44", ic_mldsa::sign44);
                mldsa_rows!("ML-DSA-65", ic_mldsa::sign);
                mldsa_rows!("ML-DSA-87", ic_mldsa::sign87);
            }
        })
        .expect("spawn measurement thread");
    worker.join().expect("measurement thread");
}
