//! Throughput measurement for the accelerated backends.

use ac_core::traits::{Aead, BlockCipher};
use std::time::Instant;

fn mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64) / secs / (1024.0 * 1024.0)
}

/// Not run by default: it is a measurement, not an assertion, and timings make
/// poor CI gates. Run it with:
///
///     cargo test --release -p ac-cipher --test throughput -- --ignored --nocapture
#[test]
#[ignore]
fn measure() {
    let size = 4 * 1024 * 1024;
    let mut data = vec![0u8; size];

    // AES-256 raw blocks, accelerated vs portable.
    for (label, cipher) in [
        (
            "aes-256 blocks (active)",
            ac_cipher::Aes256::new(&[0x2a; 32]).unwrap(),
        ),
        (
            "aes-256 blocks (portable)",
            ac_cipher::Aes256::new_portable(&[0x2a; 32]).unwrap(),
        ),
    ] {
        let t = Instant::now();
        cipher.encrypt_blocks(&mut data).unwrap();
        println!(
            "{label}: {:.1} MiB/s",
            mbps(size, t.elapsed().as_secs_f64())
        );
    }

    // AES-256-GCM end to end.
    let gcm = ac_cipher::Aes256Gcm::new(&[0x2a; 32]).unwrap();
    let mut tag = [0u8; 16];
    let t = Instant::now();
    gcm.seal_detached(&[0u8; 12], b"", &mut data, &mut tag)
        .unwrap();
    println!(
        "aes-256-gcm: {:.1} MiB/s",
        mbps(size, t.elapsed().as_secs_f64())
    );

    // ChaCha20-Poly1305 for comparison.
    let cc = ac_cipher::ChaCha20Poly1305::new(&[0x2a; 32]).unwrap();
    let t = Instant::now();
    cc.seal_detached(&[0u8; 12], b"", &mut data, &mut tag)
        .unwrap();
    println!(
        "chacha20-poly1305: {:.1} MiB/s",
        mbps(size, t.elapsed().as_secs_f64())
    );

    println!("aes backend: {:?}", ac_cipher::aes::active_backend());
    println!("ghash accelerated: {}", ac_cipher::gcm::ghash_accelerated());
}
