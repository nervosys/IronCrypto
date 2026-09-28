//! The ontology's account of the hardware against what the ciphers really do.
//!
//! `ic_ontology::runtime::backend()` tells an agent whether bulk AES is fast on
//! this machine, and `recommend` acts on the answer: fast means AES-GCM,
//! otherwise ChaCha20-Poly1305. The ontology cannot depend on `ic-cipher`, so
//! it cannot ask the cipher which path it took; it asks the CPU instead. That
//! leaves two answers to the same question, and only this crate can see both.
//!
//! They did disagree. The report said AES-NI plus `PCLMULQDQ` meant fast, but
//! the carry-less GHASH exists only on x86-64 with `std`. A 32-bit x86 build
//! therefore reported `hardware-accelerated`, and `recommend` chose AES-GCM,
//! which ran there at about 11 MiB/s against 450 for the ChaCha20-Poly1305 it
//! had rejected. The ontology's own test could not see it: it compared the
//! report with the same formula the report was computed from.
//!
//! Run on one machine this checks one configuration. It separates the cases
//! that matter only where it is run on them -- a 32-bit x86 build, an ARM
//! build -- which is why it is cheap enough to run everywhere.

use ic_cipher::aes::{active_backend, Backend};
use ic_ontology::runtime;

#[test]
fn the_reported_backend_is_the_one_aes_gcm_uses() {
    let aes = active_backend() != Backend::Portable;
    let ghash = ic_cipher::gcm::ghash_accelerated();
    let fast = aes && ghash;

    assert_eq!(
        runtime::backend().fast_bulk_symmetric(),
        fast,
        "the ontology reports {:?}, but AES is {:?} and GHASH is {}",
        runtime::backend(),
        active_backend(),
        if ghash { "carry-less" } else { "portable" },
    );
    assert_eq!(runtime::has("hardware-acceleration"), fast);
}
