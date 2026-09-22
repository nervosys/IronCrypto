//! Throughput of IronCrypto against RustCrypto, on the same buffer.
//!
//! Run it twice, because there are two honest comparisons and conflating them
//! is how a benchmark misleads:
//!
//! ```text
//! cargo run --release -- hw
//! RUSTFLAGS="--cfg aes_force_soft" cargo run --release -- soft
//! ```
//!
//! RustCrypto's `aes` 0.8 selects its software path with a cfg flag rather than
//! a Cargo feature, so the second form rebuilds the dependency. The argument is
//! only a label: nothing in this program can detect which path `aes` was
//! compiled with, so it reports what it was told and the caller has to be
//! right about it.
//!
//! The second is the one that matters for the portable backend. RustCrypto's
//! software AES is fixsliced: constant-time and table-free, the same property
//! IronCrypto's portable path is built for. Comparing IronCrypto's software
//! path against RustCrypto's AES-NI path measures the instruction set, not the
//! implementation.
//!
//! Timings are wall-clock over a large buffer, repeated, minimum taken. A
//! minimum rather than a mean because the machine is shared with whatever else
//! is running, and interference only ever makes a result slower.

use std::time::Instant;

use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::KeyInit as GcmKeyInit;
use ic_core::traits::{Aead, BlockCipher};

/// 4 MiB, big enough that per-call overhead is not what is being measured.
const SIZE: usize = 4 * 1024 * 1024;

/// Enough repeats to see a stable minimum without the slow paths taking all
/// afternoon. The portable AES path is thousands of times slower than the
/// rest, so it gets its own smaller buffer below.
const REPEATS: usize = 5;

fn mib_s(bytes: usize, secs: f64) -> f64 {
    (bytes as f64) / secs / (1024.0 * 1024.0)
}

/// Run `f` over `bytes` a few times and report the best rate seen.
fn best(label: &str, bytes: usize, repeats: usize, mut f: impl FnMut()) -> f64 {
    let mut fastest = f64::INFINITY;
    for _ in 0..repeats {
        let t = Instant::now();
        f();
        let s = t.elapsed().as_secs_f64();
        if s < fastest {
            fastest = s;
        }
    }
    let rate = mib_s(bytes, fastest);
    println!("  {label:<38} {rate:>12.2} MiB/s");
    rate
}

fn main() {
    // A label, not a detection. See the module documentation.
    let soft = std::env::args().nth(1).as_deref() == Some("soft");
    println!();
    println!("AES-256 throughput, 4 MiB buffer, best of {REPEATS}");
    println!(
        "RustCrypto path: {}",
        if soft {
            "forced software (fixsliced)"
        } else {
            "runtime-detected (AES-NI where available)"
        }
    );
    println!("IronCrypto backend: {:?}", ic_cipher::aes::active_backend());
    println!();

    let key = [0x2au8; 32];
    let mut data = vec![0u8; SIZE];

    // -- raw block encryption ------------------------------------------------
    println!("Raw AES-256 block encryption");

    let ic_active = <ic_cipher::Aes256 as BlockCipher>::new(&key).unwrap();
    let ic_fast = best("iron-crypto (active backend)", SIZE, REPEATS, || {
        ic_active.encrypt_blocks(&mut data).unwrap();
    });

    let rc_key = aes::cipher::generic_array::GenericArray::from_slice(&key);
    let rc = aes::Aes256::new(rc_key);
    let rc_fast = best("rustcrypto aes", SIZE, REPEATS, || {
        for chunk in data.chunks_exact_mut(16) {
            let b = aes::cipher::generic_array::GenericArray::from_mut_slice(chunk);
            rc.encrypt_block(b);
        }
    });

    // The portable path is slow enough that 4 MiB would take minutes. Measure a
    // smaller buffer and report the same unit, which is a rate either way.
    let small = 64 * 1024;
    let mut small_buf = vec![0u8; small];
    let ic_portable = ic_cipher::Aes256::new_portable(&key).unwrap();
    let ic_slow = best("iron-crypto (portable backend)", small, 3, || {
        ic_portable.encrypt_blocks(&mut small_buf).unwrap();
    });

    // -- AEAD ---------------------------------------------------------------
    println!();
    println!("AES-256-GCM, sealing in place");

    let gcm = <ic_cipher::Aes256Gcm as Aead>::new(&key).unwrap();
    let mut tag = [0u8; 16];
    let ic_gcm = best("iron-crypto aes-256-gcm", SIZE, REPEATS, || {
        gcm.seal_detached(&[0u8; 12], b"", &mut data, &mut tag)
            .unwrap();
    });

    let rc_gcm_key = aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(&key);
    let rc_gcm = aes_gcm::Aes256Gcm::new(rc_gcm_key);
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    let rc_gcm_rate = best("rustcrypto aes-gcm", SIZE, REPEATS, || {
        let _ = rc_gcm.encrypt_in_place_detached(nonce, b"", &mut data).unwrap();
    });

    println!();
    println!("ChaCha20-Poly1305, for reference (no hardware path either way)");
    let cc = <ic_cipher::ChaCha20Poly1305 as Aead>::new(&key).unwrap();
    best("iron-crypto chacha20-poly1305", SIZE, REPEATS, || {
        cc.seal_detached(&[0u8; 12], b"", &mut data, &mut tag)
            .unwrap();
    });

    // -- the ratios that were actually asked about --------------------------
    println!();
    println!("Ratios");
    println!(
        "  iron-crypto portable vs rustcrypto aes    {:>10.1}x slower",
        rc_fast / ic_slow
    );
    println!(
        "  iron-crypto portable vs its own aes-ni    {:>10.1}x slower",
        ic_fast / ic_slow
    );
    println!(
        "  iron-crypto gcm vs rustcrypto aes-gcm     {:>10.2}x",
        rc_gcm_rate / ic_gcm
    );
    println!(
        "  iron-crypto blocks vs rustcrypto aes      {:>10.2}x",
        rc_fast / ic_fast
    );
    println!();
    if !soft {
        println!("Note: labelled as the hardware run. For software vs software:");
        println!("  RUSTFLAGS=\"--cfg aes_force_soft\" cargo run --release -- soft");
    }
}
