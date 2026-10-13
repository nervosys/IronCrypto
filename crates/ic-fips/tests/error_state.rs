//! The error state latches, for the policy layer and for the primitives
//! under it.
//!
//! In a file of its own because it is a process of its own: the state is
//! global and cannot be left, so entering it anywhere else would fail every
//! test that ran afterwards.

use ic_core::traits::{Aead, Digest};
use ic_core::ErrorKind;
use ic_fips::{check, enter_error_state, initialize, mode, set_mode, state, Mode, State};

#[test]
fn the_error_state_latches_and_reaches_the_primitives() {
    initialize().unwrap();
    let first = if cfg!(ic_approved_only) {
        Mode::Approved
    } else {
        Mode::Unrestricted
    };
    assert_eq!(state(), State::Operational(first));
    let cipher = ic_cipher::Aes256Gcm::new(&[7u8; 32]).unwrap();
    let mut tag = [0u8; 16];
    cipher
        .seal_detached(&[0u8; 12], b"", &mut [0u8; 8], &mut tag)
        .unwrap();

    enter_error_state();
    assert_eq!(state(), State::Error);
    assert_eq!(mode(), None);
    assert!(ic_core::module::in_error_state());

    // The policy layer: nothing works, including coming back up.
    for refused in [
        check("sha2-256").map(|_| ()),
        initialize().map(|_| ()),
        set_mode(Mode::Unrestricted),
        set_mode(Mode::Approved),
    ] {
        assert_eq!(refused.unwrap_err().kind(), ErrorKind::ModuleErrorState);
    }

    // The primitives, called directly: a key made before the failure seals
    // nothing after it, and no new key is made.
    let mut data = [0u8; 8];
    assert_eq!(
        cipher
            .seal_detached(&[1u8; 12], b"", &mut data, &mut tag)
            .unwrap_err()
            .kind(),
        ErrorKind::ModuleErrorState
    );
    assert_eq!(data, [0u8; 8], "nothing was encrypted");
    assert_eq!(
        ic_cipher::Aes256Gcm::new(&[7u8; 32])
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::ModuleErrorState)
    );

    // Hashing refuses too: a digest is output. It used to be the stated limit
    // of the gate, when `Digest::finalize` had no error to return.
    assert_eq!(
        ic_hash::Sha256::digest(b"abc").unwrap_err().kind(),
        ErrorKind::ModuleErrorState
    );

    // And the state reports itself the same whoever set it.
    ic_core::module::enter_error_state();
    assert_eq!(state(), State::Error);
}
