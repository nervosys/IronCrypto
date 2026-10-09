//! A failed conditional self-test ends the module.
//!
//! In a file of its own because it is a process of its own: the state cannot
//! be left.

use ic_core::{module, Error, ErrorKind};

#[test]
fn a_failed_conditional_self_test_enters_the_error_state() {
    // A test that passes changes nothing, however often.
    for _ in 0..3 {
        module::conditional_self_test(Ok(())).unwrap();
    }
    assert!(!module::in_error_state());
    module::operational().unwrap();

    // One that fails is passed on as it was, and the module is finished.
    let failure = Error::new(ErrorKind::SelfTestFailed, "pairwise consistency");
    let passed_on = module::conditional_self_test(Err(failure)).unwrap_err();
    assert_eq!(passed_on.kind(), ErrorKind::SelfTestFailed);
    assert!(module::in_error_state());
    assert_eq!(
        module::operational().unwrap_err().kind(),
        ErrorKind::ModuleErrorState
    );

    // A later pass does not bring it back.
    module::conditional_self_test(Ok(())).unwrap();
    assert!(module::in_error_state());
}
