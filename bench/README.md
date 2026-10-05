# Benchmarks

This package is excluded from the library workspace and is not published.
Its comparison dependencies never enter the library's dependency graph.

Build before measuring, then invoke the executable directly to avoid including
compilation in the run:

```console
cargo build --manifest-path bench/Cargo.toml --release
<target-directory>/release/ic-bench ecdh
```

`cargo metadata --manifest-path bench/Cargo.toml --no-deps --format-version 1`
reports the target directory. The executable is `ic-bench.exe` on Windows.
Without `ecdh`, the executable runs the existing full throughput suite; `soft`
labels its software-AES comparison (see the module comment in `src/main.rs`
for the required build flag).

The focused P-256 ECDH diagnostic warms both implementations, then records
twenty pairs of 200 operations, alternating which implementation runs first.
Inputs and outputs pass through `black_box`. A setup assertion compares the
shared secrets with `ic_core::ct::verify`. Fixtures are deterministic; raw
shared secrets are discarded, never used as encryption keys.

The APIs do different work: IronCrypto parses and validates the SEC1 peer on
each call, while RustCrypto receives a pre-parsed public key. The CSV batch
rows and min/median/max summaries expose the observed spread. This is an
implementation comparison, not a controlled before/after measurement of a
source change and not a constant-time test. Record CPU load, compiler, source
revision and executable hash alongside results. Run on a quiet host before
drawing performance conclusions; overlapping measurements support parity.

For a source change, build both revisions first and alternate their executions
under the same conditions, minutes apart. Preserve each run's spread and treat
effects smaller than the observed noise as unresolved.

## Stack use

`ic-bench stack [mldsa] [mlkem] [ec] [hmac]` reports each operation's peak stack use and its time.
It paints a megabyte of a 16 MiB thread's stack, runs the operation once
through a call that cannot be inlined, and finds the deepest byte that changed;
an empty operation measured the same way is subtracted. That is byte-granular
on any host, where probing for the smallest thread stack that completes is
page-granular on Linux and 64 KiB-granular on Windows. Signing and key
generation cycle through 64 inputs, so their times average over the number of
rejection attempts rather than reporting one message's. Compare two revisions
the same way as any other change: build both, then alternate their runs.
