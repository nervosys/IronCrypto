//! The first use of every curve allocates nothing.
//!
//! Under `std` the generator and basepoint tables are built on first use. A
//! caller that forbids allocation after start-up -- a TLS engine with
//! caller-owned storage, say -- reaches that first use in the middle of a
//! handshake, so building them must not touch the heap. P-256's table did:
//! it was a `Vec`, and the first ECDSA verification inside a handshake
//! allocated.
//!
//! This runs without the test harness, as its own process, because the
//! harness allocates and because only the first use of each table is the case
//! that matters. Every other test in the crate builds the tables long before
//! it would run.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ic_core::traits::{KeyAgreement, SignatureScheme};

struct Counting;

static COUNTING: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: defers every call to `System` unchanged; it only counts.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if COUNTING.load(Ordering::Relaxed) {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Allocations made while running `f`.
fn allocations_in(f: impl FnOnce()) -> usize {
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.store(true, Ordering::Relaxed);
    f();
    COUNTING.store(false, Ordering::Relaxed);
    ALLOCATIONS.load(Ordering::Relaxed) - before
}

/// A valid private key of `len` bytes: below every group order here, nonzero.
fn private_key(len: usize) -> [u8; 66] {
    let mut sk = [0x11u8; 66];
    sk[0] = 0;
    let mut out = [0u8; 66];
    out[..len].copy_from_slice(&sk[66 - len..]);
    out
}

/// Derive a public key, sign and verify: the paths that reach the tables.
fn sign_and_verify<S: SignatureScheme>() {
    let sk = private_key(S::PRIVATE_KEY_LEN);
    let sk = &sk[..S::PRIVATE_KEY_LEN];
    let mut pk = [0u8; 160];
    let mut sig = [0u8; 160];
    S::public_key(sk, &mut pk[..S::PUBLIC_KEY_LEN]).expect("public key");
    S::sign(sk, b"cold", &mut sig[..S::SIGNATURE_LEN]).expect("sign");
    S::verify(&pk[..S::PUBLIC_KEY_LEN], b"cold", &sig[..S::SIGNATURE_LEN]).expect("verify");
}

fn agree<K: KeyAgreement>() {
    let sk = private_key(K::PRIVATE_KEY_LEN);
    let sk = &sk[..K::PRIVATE_KEY_LEN];
    let mut pk = [0u8; 160];
    let mut shared = [0u8; 80];
    K::public_key(sk, &mut pk[..K::PUBLIC_KEY_LEN]).expect("public key");
    K::agree(
        sk,
        &pk[..K::PUBLIC_KEY_LEN],
        &mut shared[..K::SHARED_SECRET_LEN],
    )
    .expect("agree");
}

fn main() {
    let cases: [(&str, fn()); 8] = [
        (
            "ECDSA P-256",
            sign_and_verify::<ic_ec::p256::EcdsaP256Sha256>,
        ),
        (
            "ECDSA P-384",
            sign_and_verify::<ic_ec::p384::EcdsaP384Sha384>,
        ),
        (
            "ECDSA P-521",
            sign_and_verify::<ic_ec::p521::EcdsaP521Sha512>,
        ),
        ("Ed25519", sign_and_verify::<ic_ec::ed25519::Ed25519>),
        ("ECDH P-256", agree::<ic_ec::p256::EcdhP256>),
        ("ECDH P-384", agree::<ic_ec::p384::EcdhP384>),
        ("ECDH P-521", agree::<ic_ec::p521::EcdhP521>),
        ("X25519", agree::<ic_ec::x25519::X25519>),
    ];

    // The counter must see an allocation when one happens, or a pass means
    // nothing.
    let control = allocations_in(|| drop(std::hint::black_box(Box::new([0u8; 64]))));
    assert!(control >= 1, "the counting allocator counted nothing");

    let mut failed = 0;
    for (name, case) in cases {
        let n = allocations_in(case);
        println!("{name:<12} first use: {n} allocations");
        if n != 0 {
            failed += 1;
        }
    }
    assert_eq!(failed, 0, "{failed} curve(s) allocated on first use");
    println!("cold_tables: ok");
}
