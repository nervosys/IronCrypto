//! Focused diagnostic: retained outputs and alternating implementation order.
use ic_core::{traits::KeyAgreement, Zeroizing};
use std::{hint::black_box, time::Instant};

const ITERATIONS: usize = 200;
const BATCHES: usize = 20;

fn batch(mut operation: impl FnMut()) -> f64 {
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        operation();
    }
    start.elapsed().as_secs_f64() * 1e6 / ITERATIONS as f64
}

pub fn run() {
    // Public, deterministic benchmark fixtures, not generated production keys.
    // Raw agreement outputs are compared and discarded, never used as keys.
    let secret = Zeroizing::new([0x5au8; 32]);
    let peer_secret = Zeroizing::new([0x6bu8; 32]);
    let mut peer = [0u8; 65];
    ironcrypto::ec::EcdhP256::public_key(&*peer_secret, &mut peer).unwrap();
    let other_secret = p256::SecretKey::from_bytes((&*secret).into()).unwrap();
    let other_peer = p256::PublicKey::from_sec1_bytes(&peer).unwrap();
    let mut shared = Zeroizing::new([0u8; 32]);
    ironcrypto::ec::EcdhP256::agree(&*secret, &peer, &mut *shared).unwrap();
    let expected =
        p256::ecdh::diffie_hellman(other_secret.to_nonzero_scalar(), other_peer.as_affine());
    assert!(ic_core::ct::verify(&*shared, expected.raw_secret_bytes()));

    let mut iron = || {
        ironcrypto::ec::EcdhP256::agree(black_box(&*secret), black_box(&peer), &mut *shared)
            .unwrap();
        black_box(&*shared);
    };
    let mut other = || {
        let output = p256::ecdh::diffie_hellman(
            black_box(&other_secret).to_nonzero_scalar(),
            black_box(&other_peer).as_affine(),
        );
        black_box(output.raw_secret_bytes());
    };
    // Warm both implementations before recording any batches.
    batch(&mut iron);
    batch(&mut other);
    println!(
        "P-256 ECDH diagnostic: {BATCHES} alternating pairs, {ITERATIONS} operations per batch"
    );
    println!("IronCrypto includes SEC1 peer validation; p256 uses a pre-parsed peer.");
    println!("This compares implementations, not a before/after source change or constant-time behavior.");
    println!("batch,first,iron_us,p256_us,p256_over_iron");
    let mut iron_samples = Vec::with_capacity(BATCHES);
    let mut other_samples = Vec::with_capacity(BATCHES);
    for index in 0..BATCHES {
        let (a, b) = if index % 2 == 0 {
            (batch(&mut iron), batch(&mut other))
        } else {
            let b = batch(&mut other);
            (batch(&mut iron), b)
        };
        println!(
            "{index},{},{a:.6},{b:.6},{:.6}",
            if index % 2 == 0 { "iron" } else { "p256" },
            b / a
        );
        iron_samples.push(a);
        other_samples.push(b);
    }
    for (name, samples) in [("iron", &mut iron_samples), ("p256", &mut other_samples)] {
        samples.sort_by(f64::total_cmp);
        println!(
            "{name}: min={:.3}, median={:.3}, max={:.3} us/op",
            samples[0],
            (samples[BATCHES / 2 - 1] + samples[BATCHES / 2]) / 2.0,
            samples[BATCHES - 1]
        );
    }
}
