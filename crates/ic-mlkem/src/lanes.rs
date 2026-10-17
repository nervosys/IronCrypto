//! ML-KEM's Keccak calls, run four at a time over a four-way permutation.
//!
//! # Why a scheduler rather than batches of four
//!
//! Almost all of ML-KEM's time is Keccak, and almost all of its Keccak calls
//! are independent of one another: the `k * k` SampleNTT streams that expand
//! the matrix, the noise PRFs, and in decapsulation the hash check `H(ek)` and
//! the rejection key `J(z || c)`. A four-way permutation runs four of them
//! for little more than the price of one.
//!
//! Grouping the calls in fours fits them badly. ML-KEM-768 has nine matrix
//! entries, which is two full groups and one with three lanes idle, and
//! `H(ek)` is one stream nine permutations long that a group of four would
//! run beside three idle lanes. The calls are different lengths, and a
//! SampleNTT stream's length is not even known in advance: it squeezes until
//! it has accepted 256 candidates.
//!
//! So each lane runs a queue instead. A lane takes the next task, absorbs it
//! a block per permutation, squeezes it a block per permutation until the
//! task is satisfied, and then takes the next, while the other three lanes do
//! the same with their own tasks. Every permutation is shared by whatever
//! four tasks are in flight. In encapsulation `H(ek)` occupies one lane for
//! nine permutations while the other three expand all nine matrix entries
//! in the same nine.
//!
//! # Four lanes or eight
//!
//! Where the CPU has AVX-512 the lanes are eight, on `ic_hash::KeccakX8`:
//! one permutation of eight states costs what one of four does (194 ns
//! against 181 ns on the Zen 5 part this was measured on), because the
//! register-resident assembly kernel is bound by the dependent rounds rather
//! than by the vector pipes. [`run`] takes eight only when that saves
//! permutations; see [`eight_lanes_save_permutations`]. A schedule bound by one long hash,
//! as encapsulation's is, takes the same number of permutations on either,
//! and then four lanes do less scalar work around each. Key generation's
//! Keccak schedule went from 2.6-2.9 us to 2.3-2.4 us, decapsulation's
//! shorter.
//!
//! # Trusting it
//!
//! Each task's output is the same bytes the single-stream code produces;
//! `scheduled_tasks_match_the_single_stream_functions` checks every task
//! kind, over task lists long enough that lanes are reused and tasks of
//! different lengths finish on different permutations.
//!
//! # Constant time
//!
//! The schedule depends on the lengths of the inputs, which are fixed by the
//! parameter set, and on how many SampleNTT candidates are rejected, which
//! depends only on the public seed `rho`. The noise tasks read a fixed number
//! of bytes whatever their value, and the secret bytes they read pass
//! through a buffer that is cleared when the task completes.

use crate::poly::{Poly, N};
use crate::sample::{rej_uniform, sample_poly_cbd};
use ic_core::Zeroize;
use ic_hash::{KeccakX4, KeccakX8};

/// SHAKE128's rate, for SampleNTT.
const RATE_128: usize = 168;
/// The rate SHA3-256 and SHAKE256 share.
const RATE_256: usize = 136;

/// One Keccak call, and where its result goes.
#[derive(Clone, Copy)]
pub(crate) enum Task<'a> {
    /// 32 bytes of SHA3-256 (`domain = 0x06`) or SHAKE256 (`0x1f`) over the
    /// concatenation of `parts`, into `hashes[slot]`.
    Hash {
        parts: [&'a [u8]; 2],
        domain: u8,
        slot: usize,
    },
    /// `SampleNTT(rho || index)`, into `polys[slot]`.
    Uniform {
        rho: &'a [u8; 32],
        index: [u8; 2],
        slot: usize,
    },
    /// `SamplePolyCBD_eta(PRF_eta(seed, nonce))`, into `polys[slot]`. `eta` is
    /// 2 or 3.
    Noise {
        seed: &'a [u8; 32],
        nonce: u8,
        eta: usize,
        slot: usize,
    },
}

impl Task<'_> {
    fn rate(&self) -> usize {
        match self {
            Task::Uniform { .. } => RATE_128,
            Task::Hash { .. } | Task::Noise { .. } => RATE_256,
        }
    }

    fn domain(&self) -> u8 {
        match self {
            Task::Hash { domain, .. } => *domain,
            Task::Uniform { .. } | Task::Noise { .. } => 0x1f,
        }
    }

    /// The input, as up to two pieces.
    fn parts(&self) -> [&[u8]; 2] {
        match self {
            Task::Hash { parts, .. } => *parts,
            Task::Uniform { rho, index, .. } => [&rho[..], &index[..]],
            Task::Noise { seed, nonce, .. } => [&seed[..], core::slice::from_ref(nonce)],
        }
    }

    fn input_len(&self) -> usize {
        self.parts().iter().map(|p| p.len()).sum()
    }

    /// Blocks to absorb: every full block, then one holding the remainder
    /// and the padding.
    fn blocks(&self) -> usize {
        self.input_len() / self.rate() + 1
    }
}

/// A lane's progress through its current task.
struct Lane {
    task: usize,
    /// Blocks absorbed so far.
    absorbed: usize,
    /// Coefficients accepted so far, for SampleNTT.
    filled: usize,
    /// Noise PRF output gathered so far.
    prf: [u8; 192],
    got: usize,
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.prf.zeroize();
    }
}

/// Xor block `b` of `task`'s padded input into lane `s`.
fn absorb_block(x: &mut impl Sponges, s: usize, task: &Task<'_>, b: usize) {
    let rate = task.rate();
    let start = b * rate;
    let end = start + rate;
    let mut offset = 0;
    for part in task.parts() {
        // The overlap of this part, at [offset, offset + len), with the block.
        let lo = offset.max(start);
        let hi = (offset + part.len()).min(end);
        if lo < hi {
            x.xor_lane(s, lo - start, &part[lo - offset..hi - offset]);
        }
        offset += part.len();
    }
    if b + 1 == task.blocks() {
        x.xor_lane(s, task.input_len() - start, &[task.domain()]);
        x.xor_lane(s, rate - 1, &[0x80]);
    }
}

/// Take what `lane`'s task needs from the block lane `s` has just produced.
/// Returns whether the task is complete.
fn squeeze_block(
    x: &impl Sponges,
    s: usize,
    task: &Task<'_>,
    lane: &mut Lane,
    polys: &mut [Poly],
    hashes: &mut [[u8; 32]],
) -> bool {
    match *task {
        Task::Hash { slot, .. } => {
            if let Some(out) = hashes.get_mut(slot) {
                x.read_lane(s, 0, out);
            }
            true
        }
        Task::Uniform { slot, .. } => {
            let mut block = [0u8; RATE_128];
            x.read_lane(s, 0, &mut block);
            match polys.get_mut(slot) {
                Some(out) => {
                    lane.filled = rej_uniform(out, lane.filled, &block);
                    lane.filled >= N
                }
                None => true,
            }
        }
        Task::Noise { eta, slot, .. } => {
            let need = 64 * eta.clamp(2, 3);
            let take = (need - lane.got).min(RATE_256);
            x.read_lane(s, 0, &mut lane.prf[lane.got..lane.got + take]);
            lane.got += take;
            if lane.got < need {
                return false;
            }
            if let Some(out) = polys.get_mut(slot) {
                sample_poly_cbd(need / 64, &lane.prf[..need], out);
            }
            true
        }
    }
}

/// What the scheduler needs of a set of interleaved Keccak states: the
/// lane-by-lane interface of [`KeccakX4`] and [`KeccakX8`].
trait Sponges {
    fn reset_lane(&mut self, s: usize);
    fn xor_lane(&mut self, s: usize, offset: usize, data: &[u8]);
    fn read_lane(&self, s: usize, offset: usize, out: &mut [u8]);
    fn permute(&mut self);
}

macro_rules! sponges {
    ($t:ty) => {
        impl Sponges for $t {
            fn reset_lane(&mut self, s: usize) {
                <$t>::reset_lane(self, s)
            }
            fn xor_lane(&mut self, s: usize, offset: usize, data: &[u8]) {
                <$t>::xor_lane(self, s, offset, data)
            }
            fn read_lane(&self, s: usize, offset: usize, out: &mut [u8]) {
                <$t>::read_lane(self, s, offset, out)
            }
            fn permute(&mut self) {
                <$t>::permute(self)
            }
        }
    };
}
sponges!(KeccakX4);
sponges!(KeccakX8);

/// Run every task, writing each result to its slot: eight lanes at a time
/// where the eight-way permutation is one vector permutation, four where the
/// four-way one is.
///
/// A slot outside `polys` or `hashes` discards the result rather than
/// panicking; every caller here passes slots it sized the arrays for.
pub(crate) fn run(tasks: &[Task<'_>], polys: &mut [Poly], hashes: &mut [[u8; 32]]) {
    #[cfg(test)]
    if WIDTH_FOUR.with(|w| w.get()) {
        schedule::<_, 4>(KeccakX4::zeroed(), tasks, polys, hashes);
        return;
    }
    if KeccakX8::is_available() && eight_lanes_save_permutations(tasks) {
        schedule::<_, 8>(KeccakX8::zeroed(), tasks, polys, hashes);
    } else {
        schedule::<_, 4>(KeccakX4::zeroed(), tasks, polys, hashes);
    }
}

/// Whether eight lanes need fewer permutations than four for `tasks`, estimated:
/// no fewer than the longest task, and no fewer than the work shared out
/// evenly. A SampleNTT stream is counted at three blocks, which is what
/// 256 accepted candidates usually take.
///
/// The wider permutation costs about what the narrower one does, so wider is
/// better only when it saves permutations; a schedule bound by one long hash,
/// as encapsulation's is, takes the same number either way and pays more in
/// the scalar work around each.
fn eight_lanes_save_permutations(tasks: &[Task<'_>]) -> bool {
    let (mut longest, mut total) = (0, 0);
    for task in tasks {
        let blocks = match task {
            Task::Uniform { .. } => 3,
            Task::Noise { .. } => 1,
            // Both hashes the scheduler runs are at the 136-byte rate.
            Task::Hash { parts, .. } => (parts[0].len() + parts[1].len()) / RATE_256 + 1,
        };
        longest = longest.max(blocks);
        total += blocks;
    }
    longest.max(total.div_ceil(8)) < longest.max(total.div_ceil(4))
}

#[cfg(test)]
std::thread_local! {
    /// Set to make `run` use four lanes on this thread, so the narrower
    /// schedule is tested on a CPU that would take the wider one.
    pub(crate) static WIDTH_FOUR: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// [`run`] over `x`, whatever its width: each lane takes the next task when
/// it is free.
#[inline(never)]
fn schedule<X: Sponges, const W: usize>(
    mut x: X,
    tasks: &[Task<'_>],
    polys: &mut [Poly],
    hashes: &mut [[u8; 32]],
) {
    let mut lanes: [Option<Lane>; W] = core::array::from_fn(|_| None);
    let mut next = 0;
    loop {
        for (s, slot) in lanes.iter_mut().enumerate() {
            loop {
                match slot {
                    None => {
                        let Some(task) = tasks.get(next) else {
                            break;
                        };
                        x.reset_lane(s);
                        absorb_block(&mut x, s, task, 0);
                        *slot = Some(Lane {
                            task: next,
                            absorbed: 1,
                            filled: 0,
                            prf: [0u8; 192],
                            got: 0,
                        });
                        next += 1;
                        break;
                    }
                    Some(lane) => {
                        let task = &tasks[lane.task];
                        if lane.absorbed < task.blocks() {
                            absorb_block(&mut x, s, task, lane.absorbed);
                            lane.absorbed += 1;
                            break;
                        }
                        // The permutation since the last visit produced a
                        // block of output.
                        if squeeze_block(&x, s, task, lane, polys, hashes) {
                            // Done: the lane is free for the next task now,
                            // in this same step.
                            *slot = None;
                            continue;
                        }
                        break;
                    }
                }
            }
        }
        if lanes.iter().all(Option::is_none) {
            break;
        }
        x.permute();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{sample_noise, sample_ntt};
    use ic_core::traits::{Digest, Xof};

    /// Every task kind, mixed, in a list long enough that every lane is
    /// reused several times and tasks finish on different permutations:
    /// two long hashes of different lengths first, as decapsulation has
    /// them, then matrix entries and noise at both widths interleaved.
    #[test]
    fn scheduled_tasks_match_the_single_stream_functions() {
        check_scheduled_tasks();
    }

    /// The same on four lanes, which a CPU with the eight-way permutation
    /// would not otherwise run.
    #[test]
    fn four_lane_schedule_matches_the_single_stream_functions() {
        WIDTH_FOUR.with(|w| w.set(true));
        check_scheduled_tasks();
        WIDTH_FOUR.with(|w| w.set(false));
    }

    /// Eight lanes explicitly, whatever the CPU: on one without AVX-512 the
    /// eight permutations are eight scalar ones, which is the same function.
    #[test]
    fn eight_lane_schedule_matches_the_single_stream_functions() {
        let rho = [0x42u8; 32];
        let mut tasks = Vec::new();
        let mut want = Vec::new();
        for n in 0..23u8 {
            tasks.push(Task::Uniform {
                rho: &rho,
                index: [n % 5, n / 5],
                slot: n as usize,
            });
            want.push(sample_ntt(&rho, n % 5, n / 5));
        }
        let mut polys = vec![Poly::ZERO; want.len()];
        schedule::<_, 8>(KeccakX8::zeroed(), &tasks, &mut polys, &mut []);
        assert!(polys == want);
    }

    /// The cost of ML-KEM-768 key generation's Keccak schedule alone, at each
    /// lane width. A measurement, not an assertion.
    #[test]
    #[ignore = "diagnostic, not a test"]
    fn keygen_schedule_cost() {
        use std::time::Instant;
        let rho = [0x42u8; 32];
        let sigma = [0x43u8; 32];
        let tasks: Vec<Task<'_>> = (0..15usize)
            .map(|n| {
                if n < 9 {
                    Task::Uniform {
                        rho: &rho,
                        index: [(n / 3) as u8, (n % 3) as u8],
                        slot: n,
                    }
                } else {
                    Task::Noise {
                        seed: &sigma,
                        nonce: (n - 9) as u8,
                        eta: 2,
                        slot: n,
                    }
                }
            })
            .collect();
        let mut polys = vec![Poly::ZERO; 15];
        let n = 5000;
        let mut best = [f64::INFINITY; 2];
        for _ in 0..20 {
            let t = Instant::now();
            for _ in 0..n {
                schedule::<_, 4>(KeccakX4::zeroed(), &tasks, &mut polys, &mut []);
            }
            best[0] = best[0].min(t.elapsed().as_secs_f64() / n as f64 * 1e6);
            let t = Instant::now();
            for _ in 0..n {
                schedule::<_, 8>(KeccakX8::zeroed(), &tasks, &mut polys, &mut []);
            }
            best[1] = best[1].min(t.elapsed().as_secs_f64() / n as f64 * 1e6);
        }
        println!(
            "\n  keygen: 4 lanes {:.3} us, 8 lanes {:.3} us",
            best[0], best[1]
        );

        // Encapsulation's: H(ek) first, then the nine matrix entries.
        let ek = vec![0x11u8; 1184];
        let mut tasks = vec![Task::Hash {
            parts: [&ek, &[]],
            domain: 0x06,
            slot: 0,
        }];
        for n in 0..9usize {
            tasks.push(Task::Uniform {
                rho: &rho,
                index: [(n / 3) as u8, (n % 3) as u8],
                slot: n,
            });
        }
        let mut hashes = [[0u8; 32]];
        let mut best = [f64::INFINITY; 2];
        for _ in 0..20 {
            let t = Instant::now();
            for _ in 0..n {
                schedule::<_, 4>(KeccakX4::zeroed(), &tasks, &mut polys, &mut hashes);
            }
            best[0] = best[0].min(t.elapsed().as_secs_f64() / n as f64 * 1e6);
            let t = Instant::now();
            for _ in 0..n {
                schedule::<_, 8>(KeccakX8::zeroed(), &tasks, &mut polys, &mut hashes);
            }
            best[1] = best[1].min(t.elapsed().as_secs_f64() / n as f64 * 1e6);
        }
        println!(
            "  encaps: 4 lanes {:.3} us, 8 lanes {:.3} us",
            best[0], best[1]
        );
    }

    #[test]
    #[ignore = "diagnostic, not a test"]
    fn prepared_decapsulation_width() {
        use crate::kem as m;
        use std::time::Instant;
        let mut ek = Box::new([0u8; m::ENCAPS_KEY_LEN]);
        let mut dk = Box::new([0u8; m::DECAPS_KEY_LEN]);
        let mut ct = Box::new([0u8; m::CIPHERTEXT_LEN]);
        let mut ss = [0u8; 32];
        crate::MlKem768::keygen_deterministic(&[1; 32], &[2; 32], &mut ek, &mut dk).unwrap();
        crate::MlKem768::encapsulate_deterministic(&[3; 32], &ek, &mut ct, &mut ss).unwrap();
        let p = m::PreparedDecapsulationKey::new(&dk).unwrap();
        let n = 3000;
        let mut best = [f64::INFINITY; 2];
        for _ in 0..30 {
            for (i, four) in [false, true].into_iter().enumerate() {
                WIDTH_FOUR.with(|w| w.set(four));
                let t = Instant::now();
                for _ in 0..n {
                    p.decapsulate(&ct, &mut ss).unwrap();
                }
                best[i] = best[i].min(t.elapsed().as_secs_f64() / n as f64 * 1e6);
            }
        }
        WIDTH_FOUR.with(|w| w.set(false));
        println!(
            "\n  prepared decaps: chosen {:.3} us, four lanes {:.3} us",
            best[0], best[1]
        );

        // As the bench runs it: a batch of key generations and prepared
        // encapsulations, then the decapsulations.
        let pe = m::PreparedEncapsulationKey::new(&ek).unwrap();
        let mut after = f64::INFINITY;
        for _ in 0..5 {
            for _ in 0..2000 {
                crate::MlKem768::keygen_deterministic(&[1; 32], &[2; 32], &mut ek, &mut dk)
                    .unwrap();
            }
            for _ in 0..2000 {
                pe.encapsulate_deterministic(&[3; 32], &mut ct, &mut ss)
                    .unwrap();
            }
            let t = Instant::now();
            for _ in 0..2000 {
                p.decapsulate(&ct, &mut ss).unwrap();
            }
            after = after.min(t.elapsed().as_secs_f64() / 2000.0 * 1e6);
        }
        println!("  prepared decaps after keygen and encaps batches: {after:.3} us");
    }

    fn check_scheduled_tasks() {
        let ek: Vec<u8> = (0..1184u32).map(|i| (i * 7 + 1) as u8).collect();
        let z = [0x5au8; 32];
        let ct: Vec<u8> = (0..1088u32).map(|i| (i * 13 + 5) as u8).collect();
        let rho = [0x31u8; 32];
        let sigma = [0x77u8; 32];

        let mut tasks = vec![
            Task::Hash {
                parts: [&ek, &[]],
                domain: 0x06,
                slot: 0,
            },
            Task::Hash {
                parts: [&z, &ct],
                domain: 0x1f,
                slot: 1,
            },
        ];
        let mut want_polys = Vec::new();
        for n in 0..20u8 {
            let slot = want_polys.len();
            if n % 3 == 2 {
                let eta = 2 + (n as usize % 2);
                tasks.push(Task::Noise {
                    seed: &sigma,
                    nonce: n,
                    eta,
                    slot,
                });
                want_polys.push(sample_noise(eta, &sigma, n));
            } else {
                let index = [n % 4, n / 4];
                tasks.push(Task::Uniform {
                    rho: &rho,
                    index,
                    slot,
                });
                want_polys.push(sample_ntt(&rho, index[0], index[1]));
            }
        }

        let mut polys = vec![Poly::ZERO; want_polys.len()];
        let mut hashes = [[0u8; 32]; 2];
        run(&tasks, &mut polys, &mut hashes);

        assert_eq!(hashes[0], ic_hash::Sha3_256::digest(&ek).unwrap(), "H(ek)");
        let mut j = ic_hash::Shake256::default();
        Xof::update(&mut j, &z);
        Xof::update(&mut j, &ct);
        let mut want_j = [0u8; 32];
        j.finalize_xof(&mut want_j).unwrap();
        assert_eq!(hashes[1], want_j, "J(z || c)");
        for (i, (got, want)) in polys.iter().zip(want_polys.iter()).enumerate() {
            assert_eq!(got, want, "task {i}");
        }
    }

    /// An empty list finishes, and a single task on a lone lane is right.
    #[test]
    fn short_task_lists_complete() {
        run(&[], &mut [], &mut []);
        let rho = [9u8; 32];
        let mut polys = [Poly::ZERO];
        run(
            &[Task::Uniform {
                rho: &rho,
                index: [2, 1],
                slot: 0,
            }],
            &mut polys,
            &mut [],
        );
        assert_eq!(polys[0], sample_ntt(&rho, 2, 1));
    }
}
