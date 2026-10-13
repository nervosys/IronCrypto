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
use ic_hash::KeccakX4;

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
fn absorb_block(x: &mut KeccakX4, s: usize, task: &Task<'_>, b: usize) {
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
    x: &KeccakX4,
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

/// Run every task, four lanes at a time, writing each result to its slot.
///
/// A slot outside `polys` or `hashes` discards the result rather than
/// panicking; every caller here passes slots it sized the arrays for.
pub(crate) fn run(tasks: &[Task<'_>], polys: &mut [Poly], hashes: &mut [[u8; 32]]) {
    let mut x = KeccakX4::zeroed();
    let mut lanes: [Option<Lane>; 4] = [None, None, None, None];
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
