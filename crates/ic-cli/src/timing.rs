//! A leakage detector, in the style of dudect.
//!
//! `CWE-208` is recorded as [`Partial`](ic_ontology::standards::Compliance) in
//! the frameworks knowledgebase, with the gap stated as: constant-time
//! construction here is *argued and reviewed, not measured*, and an argument is
//! not evidence. This is the measurement half.
//!
//! # Why it is a tool and not a test
//!
//! It does not run in CI and nothing gates on it. Timing measurement needs a
//! quiet machine, and a test that fails when a laptop decides to index its disk
//! teaches people to ignore failures — which costs more than the test was ever
//! worth. So this reports, and a human reads it.
//!
//! # The method
//!
//! Two input classes, interleaved at random so that clock drift, frequency
//! scaling and scheduler noise land on both classes equally rather than on
//! whichever ran second. Execution times are accumulated per class and compared
//! with Welch's t-test, which does not assume the two have equal variance.
//!
//! A large `|t|` means the two classes are distinguishable by timing, which for
//! a secret-dependent input class means the secret is leaking. A small `|t|`
//! means *this run found no evidence of leakage*, which is not the same as
//! proving there is none: absence of evidence from a noisy machine is weak
//! evidence of absence, and the report says so rather than printing a tick.
//!
//! # The positive control
//!
//! [`Target::NaiveCompare`] is a deliberately variable-time comparison that
//! bails on the first differing byte. It exists because a leakage detector that
//! has never detected leakage proves nothing — it could be measuring the wrong
//! thing, cropping away the signal, or timing an operation the optimiser
//! removed. The control must show a large `|t|`. If it does not, no other
//! result in the run means anything, and the report leads with that rather than
//! leaving a reader to notice.

use ic_json::Json;
use std::time::Instant;

/// How distinguishable two timing distributions are.
///
/// The thresholds follow dudect's convention. They are conventions, not
/// theorems, which is why the report carries the number as well as the verdict.
const T_LEAKING: f64 = 10.0;
const T_SUSPICIOUS: f64 = 5.0;

/// What can be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Positive control: an early-exit comparison that must show leakage.
    NaiveCompare,
    /// The constant-time comparison every tag and signature check uses.
    CtVerify,
    /// AEAD tag verification, through the public API.
    AeadOpen,
    /// Scalar multiplication on P-256, with a fixed versus a random scalar.
    P256ScalarMul,
    /// X25519, likewise.
    X25519,
}

impl Target {
    /// Every target, in the order the report presents them.
    ///
    /// The control is first so a reader meets it before any result that depends
    /// on it being believable.
    pub const ALL: &'static [Target] = &[
        Target::NaiveCompare,
        Target::CtVerify,
        Target::AeadOpen,
        Target::P256ScalarMul,
        Target::X25519,
    ];

    /// Stable identifier, as the command line accepts it.
    pub const fn id(self) -> &'static str {
        match self {
            Self::NaiveCompare => "naive-compare",
            Self::CtVerify => "ct-verify",
            Self::AeadOpen => "aead-open",
            Self::P256ScalarMul => "p256-scalarmul",
            Self::X25519 => "x25519",
        }
    }

    /// What the two input classes are, so a reader can judge the result.
    pub const fn classes(self) -> &'static str {
        match self {
            Self::NaiveCompare | Self::CtVerify => {
                "equal buffers, versus buffers differing in the first byte"
            }
            Self::AeadOpen => "a correct tag, versus a tag wrong in the first byte",
            Self::P256ScalarMul | Self::X25519 => "a fixed scalar, versus a random scalar",
        }
    }

    /// Whether this target is expected to leak.
    ///
    /// Only the control is. Everything else is expected not to, and the report
    /// compares against this rather than letting a reader supply the
    /// expectation from memory.
    pub const fn expected_to_leak(self) -> bool {
        matches!(self, Self::NaiveCompare)
    }

    /// A documented, benign reason this target shows a timing difference.
    ///
    /// Without this a known and harmless difference reads as a finding, and a
    /// report that cries wolf gets ignored -- taking the real findings with it.
    /// A reason here is a claim that the branch is on something already public,
    /// and it has to survive being read by someone sceptical.
    pub const fn known_difference(self) -> Option<&'static str> {
        match self {
            Self::AeadOpen => Some(
                "The tag comparison is constant time; ct-verify measures it directly and shows no difference. What differs is that the failure path zeroizes the output buffer and the success path does not. That branch is on whether the tag verified, which the caller already learns from the returned error, so it reveals nothing about the key or the plaintext. It is not free, though: a caller trying to hide whether authentication failed -- to deny an attacker a decryption oracle -- cannot assume this is invisible, and should add its own constant-time handling above this layer.",
            ),
            _ => None,
        }
    }

    fn parse(id: &str) -> Option<Target> {
        Self::ALL.iter().copied().find(|t| t.id() == id)
    }
}

/// Running mean and variance, by Welford's method.
///
/// Accumulating rather than storing avoids a second pass and keeps the sample
/// count unbounded, which matters because the useful signal here is often small
/// and only separates from the noise after a lot of samples.
#[derive(Default, Clone, Copy)]
struct Stats {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Stats {
    fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }

    fn variance(&self) -> f64 {
        if self.n < 2 {
            0.0
        } else {
            self.m2 / (self.n - 1) as f64
        }
    }
}

/// Welch's t-statistic for two independent samples.
///
/// Welch rather than Student because the two classes routinely have different
/// variance — a branch that exits early is not merely faster on average, it is
/// also less variable, and assuming equal variance would throw that away.
fn welch_t(a: &Stats, b: &Stats) -> f64 {
    if a.n < 2 || b.n < 2 {
        return 0.0;
    }
    let denominator = (a.variance() / a.n as f64) + (b.variance() / b.n as f64);
    if denominator <= 0.0 {
        return 0.0;
    }
    (a.mean - b.mean) / denominator.sqrt()
}

/// The outcome of measuring one target.
pub struct Report {
    /// What was measured.
    pub target: Target,
    /// The t-statistic, cropped and uncropped, whichever is larger in size.
    pub t: f64,
    /// How many timings were taken in total.
    pub samples: usize,
    /// Whether the number exceeds the leaking threshold.
    pub leaking: bool,
    /// Whether the result matches what this target should show.
    pub as_expected: bool,
}

/// A small deterministic generator for class selection and input material.
///
/// Deterministic so a surprising result can be re-run identically. The class
/// sequence does not need to be unpredictable to an adversary — it needs to be
/// uncorrelated with anything the machine is doing, and this is.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = (self.next() & 0xff) as u8;
        }
    }
}

/// An early-exit comparison. The positive control, and nothing else.
///
/// `#[inline(never)]` because the whole point is to time it, and an inlined
/// version could be reordered into the measurement loop in ways that blur what
/// is being measured.
#[inline(never)]
fn naive_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            return false;
        }
    }
    true
}

/// Time one operation for the given class, returning nanoseconds.
///
/// The result of the operation is returned to the caller and folded into a
/// running accumulator, so the optimiser cannot discard the call as dead.
fn time_once(target: Target, class: u8, rng: &mut Rng, sink: &mut u64) -> f64 {
    use ic_core::traits::{Aead, KeyAgreement};

    match target {
        Target::NaiveCompare | Target::CtVerify => {
            let mut a = [0u8; 64];
            rng.fill(&mut a);
            let mut b = a;
            if class == 1 {
                b[0] ^= 0xff;
            }
            let start = Instant::now();
            let out = if target == Target::NaiveCompare {
                naive_compare(&a, &b)
            } else {
                ic_core::ct::verify(&a, &b)
            };
            let elapsed = start.elapsed().as_nanos() as f64;
            *sink = sink.wrapping_add(out as u64);
            elapsed
        }
        Target::AeadOpen => {
            let aead = ic_cipher::Aes256Gcm::new(&[0x11u8; 32]).unwrap();
            let nonce = [0x22u8; 12];
            let mut buf = [0x33u8; 64];
            let mut tag = [0u8; 16];
            aead.seal_detached(&nonce, b"", &mut buf, &mut tag).unwrap();
            if class == 1 {
                tag[0] ^= 0xff;
            }
            let start = Instant::now();
            let out = aead.open_detached(&nonce, b"", &mut buf, &tag);
            let elapsed = start.elapsed().as_nanos() as f64;
            *sink = sink.wrapping_add(out.is_ok() as u64);
            elapsed
        }
        Target::P256ScalarMul => {
            let mut sk = [0x07u8; 32];
            if class == 1 {
                rng.fill(&mut sk);
                // Keep it a plausible scalar rather than risking a rejection
                // path, which would time a different thing entirely.
                sk[0] &= 0x7f;
                sk[31] |= 1;
            }
            let mut peer = [0u8; 65];
            ic_ec::p256::EcdhP256::public_key(&[0x05u8; 32], &mut peer).unwrap();
            let mut shared = [0u8; 32];
            let start = Instant::now();
            let out = ic_ec::p256::EcdhP256::agree(&sk, &peer, &mut shared);
            let elapsed = start.elapsed().as_nanos() as f64;
            *sink = sink
                .wrapping_add(out.is_ok() as u64)
                .wrapping_add(shared[0] as u64);
            elapsed
        }
        Target::X25519 => {
            let mut sk = [0x07u8; 32];
            if class == 1 {
                rng.fill(&mut sk);
            }
            let mut peer = [0u8; 32];
            ic_ec::X25519::public_key(&[0x05u8; 32], &mut peer).unwrap();
            let mut shared = [0u8; 32];
            let start = Instant::now();
            let out = ic_ec::X25519::agree(&sk, &peer, &mut shared);
            let elapsed = start.elapsed().as_nanos() as f64;
            *sink = sink
                .wrapping_add(out.is_ok() as u64)
                .wrapping_add(shared[0] as u64);
            elapsed
        }
    }
}

/// Measure one target.
pub fn measure(target: Target, iterations: usize) -> Report {
    let mut rng = Rng(0x7a17_1234_5678_9abc);
    let mut sink = 0u64;

    // Warm up: the first calls pay for page faults, branch predictor training
    // and frequency ramp, none of which is what is being measured.
    for i in 0..(iterations / 20).max(100) {
        time_once(target, (i % 2) as u8, &mut rng, &mut sink);
    }

    let mut samples: Vec<(u8, f64)> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        // Interleave at random, so drift affects both classes alike.
        let class = (rng.next() & 1) as u8;
        let ns = time_once(target, class, &mut rng, &mut sink);
        samples.push((class, ns));
    }

    // Uncropped.
    let mut a = Stats::default();
    let mut b = Stats::default();
    for (class, ns) in &samples {
        if *class == 0 {
            a.push(*ns)
        } else {
            b.push(*ns)
        }
    }
    let mut best = welch_t(&a, &b);

    // Cropped. A preemption or an interrupt lands in one class at random and
    // produces an enormous outlier, which inflates the variance and *hides*
    // real leakage. Discarding the tail is what dudect does, and taking the
    // largest statistic across thresholds is what keeps a single arbitrary
    // cutoff from deciding the answer.
    let mut sorted: Vec<f64> = samples.iter().map(|(_, ns)| *ns).collect();
    sorted.sort_by(|x, y| x.partial_cmp(y).unwrap_or(std::cmp::Ordering::Equal));
    for percentile in [0.9_f64, 0.95, 0.99] {
        let index = ((sorted.len() as f64) * percentile) as usize;
        let Some(&cutoff) = sorted.get(index.min(sorted.len().saturating_sub(1))) else {
            continue;
        };
        let mut a = Stats::default();
        let mut b = Stats::default();
        for (class, ns) in &samples {
            if *ns > cutoff {
                continue;
            }
            if *class == 0 {
                a.push(*ns)
            } else {
                b.push(*ns)
            }
        }
        let t = welch_t(&a, &b);
        if t.abs() > best.abs() {
            best = t;
        }
    }

    // Keep the accumulator observable so nothing above is optimised away.
    std::hint::black_box(sink);

    let leaking = best.abs() >= T_LEAKING;
    // A documented public branch is allowed to differ. The expectation is
    // recorded per target so that a difference is judged against what the code
    // is known to do, not against a blanket hope that nothing differs.
    let as_expected =
        leaking == target.expected_to_leak() || (leaking && target.known_difference().is_some());
    Report {
        target,
        t: best,
        samples: samples.len(),
        leaking,
        as_expected,
    }
}

/// Run one target, or all of them, and render the result.
pub fn run(target: Option<&str>, iterations: usize) -> Result<Json, String> {
    let targets: Vec<Target> = match target {
        None => Target::ALL.to_vec(),
        Some(id) => vec![Target::parse(id)
            .ok_or_else(|| format!("unknown target '{id}'; try one of {}", target_list()))?],
    };

    let reports: Vec<Report> = targets.iter().map(|t| measure(*t, iterations)).collect();

    // The control decides whether anything else is worth reading.
    let control = reports.iter().find(|r| r.target.expected_to_leak());
    let control_ok = control.map(|r| r.leaking).unwrap_or(false);

    let items: Vec<Json> = reports
        .iter()
        .map(|r| {
            let verdict = if r.leaking && r.target.known_difference().is_some() {
                "differs, for a documented and public reason"
            } else if r.leaking {
                "leaking"
            } else if r.t.abs() >= T_SUSPICIOUS {
                "suspicious"
            } else {
                "no evidence of leakage"
            };
            Json::object([
                ("target", Json::str(r.target.id())),
                ("classes", Json::str(r.target.classes())),
                ("t", Json::Number((r.t * 100.0).round() / 100.0)),
                ("samples", Json::Number(r.samples as f64)),
                ("verdict", Json::str(verdict)),
                ("expected_to_leak", Json::Bool(r.target.expected_to_leak())),
                ("as_expected", Json::Bool(r.as_expected)),
                (
                    "known_difference",
                    match r.target.known_difference() {
                        Some(why) => Json::str(why),
                        None => Json::Null,
                    },
                ),
            ])
        })
        .collect();

    Ok(Json::object([
        ("control_detected_leakage", Json::Bool(control_ok)),
        (
            "interpretation",
            Json::str(if control.is_none() {
                "The positive control was not run, so a null result here establishes nothing \
                 about the measurement itself. Run without a target to include it."
            } else if control_ok {
                "The positive control showed leakage, so the measurement can detect it. A null \
                 result on the other targets is therefore meaningful, but still only says that \
                 this run found no evidence on this machine. It is not a proof of constant \
                 time."
            } else {
                "THE POSITIVE CONTROL DID NOT SHOW LEAKAGE. The measurement is not working -- \
                 too few iterations, a machine too noisy, or an operation the optimiser \
                 removed. Every other result in this run is meaningless."
            }),
        ),
        (
            "thresholds",
            Json::object([
                ("leaking", Json::Number(T_LEAKING)),
                ("suspicious", Json::Number(T_SUSPICIOUS)),
            ]),
        ),
        ("results", Json::Array(items)),
    ]))
}

/// The targets, for help text and error messages.
pub fn target_list() -> String {
    Target::ALL
        .iter()
        .map(|t| t.id())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Welch's t-statistic, against hand-computed values.
    ///
    /// The statistic is the whole instrument, so it is checked against
    /// arithmetic rather than against its own output.
    #[test]
    fn the_statistic_matches_its_definition() {
        let mut a = Stats::default();
        let mut b = Stats::default();
        for x in [1.0, 2.0, 3.0, 4.0, 5.0] {
            a.push(x);
        }
        for x in [1.0, 2.0, 3.0, 4.0, 5.0] {
            b.push(x);
        }
        assert_eq!(a.mean, 3.0);
        assert_eq!(a.variance(), 2.5);
        // Identical samples cannot be distinguished.
        assert!(welch_t(&a, &b).abs() < 1e-12);

        // A clean separation with tiny variance gives a large statistic.
        let mut c = Stats::default();
        for x in [100.0, 100.1, 99.9, 100.0] {
            c.push(x);
        }
        assert!(
            welch_t(&a, &c).abs() > 100.0,
            "well-separated samples should be obvious: {}",
            welch_t(&a, &c)
        );

        // Degenerate inputs must not divide by zero.
        let empty = Stats::default();
        assert_eq!(welch_t(&empty, &empty), 0.0);
        assert_eq!(welch_t(&a, &empty), 0.0);
    }

    /// The control must detect the leak it is built to detect.
    ///
    /// This is the one part of the harness that can be tested in CI without
    /// measuring anything real: an early-exit comparison over 64 bytes, where
    /// one class differs at byte zero, is such a gross difference that even a
    /// loaded machine separates the two classes. If this ever stops firing, the
    /// tool has stopped measuring and its null results are worthless.
    ///
    /// Note what is *not* asserted: nothing here claims the other targets are
    /// constant time. That is a measurement for a quiet machine, reported by
    /// the tool and read by a person.
    #[test]
    fn the_positive_control_detects_its_own_leak() {
        let report = measure(Target::NaiveCompare, 20_000);
        assert!(
            report.leaking,
            "the positive control failed to detect an early-exit comparison: t = {:.2}. \
             Either the harness is broken or this machine is too loaded to measure on.",
            report.t
        );
        assert!(report.as_expected);
        assert_eq!(report.samples, 20_000);
    }

    /// A known difference must explain itself, and must not be a blanket
    /// excuse.
    ///
    /// Exactly one target has one. If this list ever grew quietly it would
    /// become the place inconvenient measurements go to be dismissed, which is
    /// the failure mode that makes leakage reports worthless.
    #[test]
    fn known_differences_are_few_and_justified() {
        let with = Target::ALL
            .iter()
            .filter(|t| t.known_difference().is_some())
            .count();
        assert_eq!(with, 1, "only the AEAD open path should have one");

        let why = Target::AeadOpen.known_difference().unwrap();
        assert!(
            why.contains("constant time"),
            "it must say the comparison itself is constant time"
        );
        assert!(
            why.contains("zeroizes the output buffer"),
            "it must name the actual cause"
        );
        assert!(
            why.contains("cannot assume this is invisible"),
            "it must state the case where the difference still matters"
        );
        assert!(
            Target::CtVerify.known_difference().is_none(),
            "the constant-time comparison gets no excuse"
        );

        // This text is printed. Two spaces in the middle of a sentence is the
        // signature of a wrapped literal gone wrong, and it has caught real
        // damage twice in the ontology crate.
        const RUN: &str = "  ";
        assert_eq!(RUN.len(), 2, "the guard's own pattern was rewritten");
        for t in Target::ALL {
            assert!(!t.classes().contains(RUN), "{} classes", t.id());
            if let Some(why) = t.known_difference() {
                assert!(!why.contains(RUN), "{} known_difference", t.id());
            }
        }
    }

    /// An unknown target is a correctable error, not a panic.
    #[test]
    fn unknown_targets_are_reported() {
        assert!(run(Some("no-such-target"), 10).is_err());
        assert!(Target::parse("ct-verify").is_some());
        assert!(Target::parse("nonsense").is_none());
    }

    /// The report must lead with whether it can be believed.
    #[test]
    fn the_report_states_whether_the_control_passed() {
        let json = run(Some("ct-verify"), 200).unwrap();
        // Run without the control, the interpretation must say so rather than
        // presenting a null result as reassurance.
        assert_eq!(
            json.get("control_detected_leakage").unwrap().as_bool(),
            Some(false)
        );
        let text = json.get("interpretation").unwrap().as_str().unwrap();
        assert!(
            text.contains("establishes nothing"),
            "a run without the control must say the result is not meaningful: {text}"
        );

        let results = json.get("results").unwrap().as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].get("t").is_some());
        assert!(results[0].get("classes").is_some());
    }

    /// Every target must be runnable and describe itself.
    #[test]
    fn every_target_runs_and_is_described() {
        for target in Target::ALL {
            assert!(!target.id().is_empty());
            assert!(
                target.classes().len() > 20,
                "{} must say what its classes are",
                target.id()
            );
            // A tiny run, only to prove the target is wired up and returns.
            let r = measure(*target, 50);
            assert_eq!(r.samples, 50);
            assert!(r.t.is_finite(), "{} produced a non-finite t", target.id());
        }
        assert_eq!(
            Target::ALL.iter().filter(|t| t.expected_to_leak()).count(),
            1,
            "there must be exactly one positive control"
        );
    }
}
