# Continuous integration

Four things gate this project, and they run the same script on purpose.

| where | what runs | when |
|---|---|---|
| `.githooks/pre-commit` | `scripts/check.sh --quick` | every commit |
| `.githooks/pre-push` | `scripts/check.sh` (adds cross-compilation) | every push |
| `.github/workflows/self-hosted.yml` | `scripts/check.sh` | every push, on a runner you provide |
| `.github/workflows/ci.yml` | the same gates, across three OSes, four no_std targets and five
compiled-code targets | every push, on GitHub-hosted runners |

Enable the hooks once per clone:

```bash
git config core.hooksPath .githooks
```

Both hooks can be skipped deliberately with `--no-verify`. That escape hatch is
there because a hook nobody can bypass gets disabled entirely the first time it
is inconvenient, and then it protects nothing.

## Why there is a self-hosted workflow

`ci.yml` is correct and does not run. Every job on this repository is rejected
before it starts:

> The job was not started because recent account payments have failed or your
> spending limit needs to be increased.

That is an account-level block on the `nervosys` organisation. Actions is
enabled on the repository, minutes are billed to the organisation, and nothing
configured inside a repository can lift it — GitHub has no per-repository
Actions budget. The two ways out are to clear the billing, or to run the jobs
somewhere that does not consume GitHub minutes.

A self-hosted runner does the latter. It is free on a private repository and
works whatever the billing state, so `self-hosted.yml` keeps working if billing
lapses again. Once billing is restored, `ci.yml` resumes and gives what a single
runner cannot: the three-OS matrix, the release-mode test run, and the
cross-compilation targets built on a clean machine.

## Registering a runner

From the repository page: **Settings → Actions → Runners → New self-hosted
runner**, then follow the commands it prints. It gives a registration token
valid for one hour.

From the command line, which is the same thing:

```bash
# A registration token, valid for one hour. Needs admin on the repository.
gh api -X POST repos/nervosys/IronCrypto/actions/runners/registration-token \
  --jq .token
```

Then, on the machine that will run the jobs. **Not inside a user profile** --
see below, it is the difference between a service that starts and one that does
not:

```powershell
mkdir C:\actions-runner; cd C:\actions-runner

# v2.337.0 was current when this was written; the page GitHub shows you when you
# add a runner always names the release it expects, with its digest.
curl -o runner.zip -L https://github.com/actions/runner/releases/download/v2.337.0/actions-runner-win-x64-2.337.0.zip
(Get-FileHash runner.zip -Algorithm SHA256).Hash.ToLower()
# 1150692afa94e71f872017e254ea55b6eece1eece3fe7e3a6d4c93d0a1b85cfc
Expand-Archive runner.zip -DestinationPath . -Force; Remove-Item runner.zip
```

Check the digest against the one on the release page before running any of it.
This is a cryptography project; downloading and executing an unverified binary
to test it would be an odd way to start.

Register it, from an **elevated** prompt:

```powershell
.\config.cmd --url https://github.com/nervosys/IronCrypto --token <TOKEN> `
  --unattended --name ironcrypto-win-x64 --labels self-hosted,windows,x64 `
  --work _work --replace --runasservice
```

`--runasservice` installs it under `NT AUTHORITY\NETWORK SERVICE`, starts it,
and sets it to start on boot. Without that flag you get `.\run.cmd`, which runs
in the foreground and dies with the terminal.

On Linux and macOS the service is a separate script instead:

```bash
./config.sh --url https://github.com/nervosys/IronCrypto --token <TOKEN>
sudo ./svc.sh install
sudo ./svc.sh start
```

There is no `svc.cmd` on Windows. The extracted Windows package contains `bin`,
`externals`, `config.cmd`, `run.cmd` and two `run-helper` templates, and nothing
else; `svc.sh` is the Unix path only.

### Put it outside the user profile

`C:\actions-runner`, not `C:\Users\<you>\actions-runner`. The service runs as
`NT AUTHORITY\NETWORK SERVICE`, which cannot traverse another account's profile
directory, and the runner checks this explicitly on startup:

```
System.UnauthorizedAccessException: Access to the path 'C:\Users\<you>' is denied.
   at GitHub.Runner.Sdk.IOUtil.ValidateExecutePermission(String directory)
```

`ValidateExecutePermission` walks every ancestor of the runner directory, so
granting permissions on the runner folder itself does not fix it -- the leaf is
already fine and the path to it is not. The service installs happily and then
fails to start, which is a confusing way to learn this.

The workflow's `runs-on: [self-hosted]` matches any runner registered to this
repository. To point it at one particular machine, give that runner a label
during `config` and add the label to the list.

### If the runner disappears

The binaries are a common antivirus false positive. If the directory empties
itself and the process vanishes together, check `Get-MpThreatDetection` and add
an exclusion for the runner folder -- another reason to keep it at a fixed path
outside the profile rather than somewhere incidental.

### What the runner needs

A Rust toolchain, and `bash` — the gate is a shell script, so on Windows that
means Git Bash, which comes with Git for Windows.

Being installed is not enough. As a service the runner uses the machine PATH,
where the first `bash.exe` is `C:\Windows\System32ash.exe` — the WSL
launcher, which exits 1 when no distribution is installed. Git Bash sits in
`Gitin`, which the machine PATH does not usually carry; it carries `Git\cmd`,
which holds `git.exe` and no `bash.exe`. So the workflow derives Git's install
root from `git.exe` and prepends its `bin` before running anything, and the
toolchain step prints which `bash` it ended up with. This only bites once the
runner is a service — run interactively it inherits a user PATH that usually has
Git Bash on it, so the failure appears exactly when the setup is made permanent.

The workflow installs the
cross-compilation targets itself and prints the toolchain version before it
starts, so a machine that has drifted shows up in the log rather than quietly
producing a different answer from everyone else's.

### One thing to know before you register one

Anyone whose workflow reaches that machine runs code on it. GitHub advises
against self-hosted runners on *public* repositories for that reason: a fork's
pull request would otherwise execute on your hardware.

This repository is public, since 2026-09-16. The runner was set up while it was
private, and for twelve days afterwards `self-hosted.yml` still ran on every
pull request, with approval required only from first-time contributors. No pull
request was opened in that time. Two things changed on 2026-09-28:

- `self-hosted.yml` no longer triggers on `pull_request`. Pull requests are
  tested by `ci.yml`, on GitHub's runners.
- The repository requires a maintainer's approval before workflows run for
  *any* outside contributor (`all_external_contributors`), not only a
  first-time one.

The second is the one that holds. A pull request runs workflow files as the
pull request has them, so removing the trigger only changes the default: its
author can restore it or add a workflow naming `self-hosted`. Approval is where
that gets caught, so read the `.github/` changes in a pull request before
approving it to run. Loosening that setting reopens the machine.

Prefer a machine you do not mind rebuilding, and note that the runner keeps its
working directory between jobs, which is why the workflow points
`CARGO_TARGET_DIR` at the runner's temp directory rather than sharing a target
directory with whatever else is on the machine.

## The ARM backends, under QEMU

The AES, `PMULL` GHASH, SHA-256 and SHA-512 backends behind the
`aarch64-crypto` feature need an AArch64 CPU to execute. `ci.yml`'s arm64 job
would run them on `macos-latest`, and is blocked with the rest. Without ARM
hardware, `scripts/test-aarch64.sh` runs their tests on an x86-64 Linux host
under QEMU user-mode emulation (`qemu-aarch64 -cpu max`, which implements
FEAT_AES, FEAT_PMULL, FEAT_SHA256 and FEAT_SHA512):

```bash
# Once. None of it needs root.
rustup target add aarch64-unknown-linux-musl
apt-get download qemu-user && dpkg -x qemu-user_*.deb ~/qemu   # Debian; a static qemu-aarch64
export QEMU_AARCH64=~/qemu/usr/bin/qemu-aarch64                 # or put it on PATH

scripts/test-aarch64.sh           # ic-core, ic-hash, ic-cipher, ic-ontology; then ironcrypto in release
scripts/test-aarch64.sh --quick   # the backends' crates only
```

There are two routes. With root, install the user-mode emulator from the
distribution:

```bash
sudo apt install qemu-user-static   # provides qemu-aarch64-static
```

`qemu-user-static` is the package that provides the user-mode
`qemu-aarch64-static`. `qemu-system-arm` and `qemu-efi-aarch64` are the full
system emulator and do not provide it.

Without root, on a Debian host where `apt-get download` works but nothing can
be installed, the same package can be unpacked into the home directory and put
on the search path. This is what was done on the WSL Debian (trixie) host:

```bash
cd ~ && mkdir -p ~/.local/qemu-dl ~/.local/bin && cd ~/.local/qemu-dl
apt-get download qemu-user        # fetches qemu-user_1:10.0.13+ds-0+deb13u1_amd64.deb
dpkg -x qemu-user_*.deb ~/.local/qemu
ln -sfn ~/.local/qemu/usr/bin/qemu-aarch64 ~/.local/bin/qemu-aarch64
~/.local/bin/qemu-aarch64 -cpu max --version   # qemu-aarch64 version 10.0.13
```

When `QEMU_AARCH64` is unset, `scripts/check.sh` and `scripts/test-aarch64.sh`
look for `qemu-aarch64`, then `qemu-aarch64-static`, on `PATH`, then the same
two names in `~/.local/bin`; no export is needed for either route. The `.deb` is about 16 MB; the download took over two minutes here, so
run it in the background if a foreground shell times out. If `apt-get download`
does not work, fetch the same file from
`https://deb.debian.org/debian/pool/main/q/qemu/` with `curl`.

The musl target links statically with `rust-lld` from the toolchain, so there
is no cross compiler and no sysroot to install. On Windows, run it inside WSL.
The script fails if a backend test reports that it skipped, or if the backend
report does not name the ARM paths: a pass that never reached the kernels is
not a pass. `scripts/check.sh` runs the `--quick` form when it finds
`qemu-aarch64` and the musl target on Linux, and says it did not otherwise.

What it establishes is that the kernels compute what the portable code
computes, with the instructions as QEMU models them, and that the facade's
vector suites pass on that path. It does not establish behaviour on a real
core, and its timings mean nothing: performance on AArch64 is unmeasured.

## Older x86-64 CPUs, under QEMU

`scripts/test-old-cpus.sh` builds every test binary for baseline x86-64 (the
musl target) and runs each one under `qemu-x86_64 -cpu <model>`, for models
with the feature sets the runtime dispatchers branch on. A hand-written AVX2,
BMI2, ADX, SHA-NI, AES-NI, PCLMULQDQ path reached without its runtime check
executes an instruction the model lacks, and the process dies with SIGILL. A
run with no SIGILL is the evidence that nothing was reached ungated on that
model.

```bash
rustup target add x86_64-unknown-linux-musl
scripts/test-old-cpus.sh                         # the default models; slow, every binary is emulated
scripts/test-old-cpus.sh Nehalem-v2 'max,-adx'   # named models only
```

It needs `qemu-x86_64` (Debian's `qemu-user`, the same package as the ARM
section above). Its exit status is non-zero on any SIGILL, timeout, or run that
reports no results. A test `FAIL` does not fail it. One check insists on its
instructions by design: ic-ec's four-limb field check needs BMI2 and ADX, and
the script sets `IC_EC_NO_ADX_OK=1` so it, and the rest of that suite, run on
models without them. The AES-GCM check
`gcm::fused_tests::every_path_matches_the_reference_at_every_length_to_600`
used to fail on models without AES-NI or PCLMULQDQ, counting comparisons a
kernel would add where the CPU has none; it now expects one comparison a case
there and two where a kernel exists, and passes on Nehalem.

Two limits. QEMU's TCG drops every AVX-512 feature from every CPU model, so
the AVX-512, IFMA and VPCLMULQDQ paths cannot be run this way, and need
hardware. And a model that
never reaches a path proves nothing about that path. Check that a model took
the fallback by its self-checks, not by its exit status alone: the fast-path
tests above are the ones that fail when the fast path did not run.

The workspace test suite (65 test binaries) was run under Intel SDE 10.13.1
on the snb, hsw, bdw, skx, icl and spr models at commit 766cfe2, all passing; IC_EC_NO_ADX_OK was set for snb and hsw, which
lack ADX. The 150 tests marked `ignored` per model (timing diagnostics, deep
fuzz runs and the 4096-bit key test, slow in debug) were not run, and the
`cold_tables` binary uses its own harness and prints `ok` rather than a test
count. This is a test run on emulated CPUs, not a claim about any hardware
or any validation.

The script is not wired into `scripts/check.sh`; it is too slow for every
commit or push.

## Why the workflows call a script instead of listing steps

`ci.yml` used to write every step out again. Its copy of the dependency check
excluded the workspace crates by name, under the `ac-` prefix they carried
before the rename — so it matched none of them, reported all sixteen workspace
crates as third-party dependencies, and would have failed every push had it been
running at all. It was already short by six crates before the rename.

That is what a second copy of a rule does. `scripts/check.sh` and
`scripts/no-third-party.sh` are the one definition; the workflows and the hooks
invoke them. `no-third-party.sh` goes further and reads the workspace members
from `Cargo.toml`, so there is no list to go stale.

`ci_and_the_local_gate_run_the_same_checks`, in `crates/ic-cli/src/sbom.rs`,
compares the workflow files against the script gate by gate and fails if either
grows its own copy of a check the other has. It compares the environment too,
not just the commands: CI set `RUSTDOCFLAGS: -D warnings` on its docs job and
the local gate did not, so nine broken intra-doc links were warnings in one
place and errors in the other, and nobody read either.

## Testing the AVX2 paths on an AVX-512 machine

On a CPU with AVX-512, the default build never runs the AVX2-only paths.
`--cfg ic_no_avx512` turns the AVX-512 detection off, so this runs the AVX2,
VAES-256 and MULX/ADX code instead -- for P-256 and P-384, the MULX/ADX
point formulas in place of the IFMA ones (`ic_ec::nist_backend()` says
which):

```bash
RUSTFLAGS="--cfg ic_no_avx512" CARGO_TARGET_DIR=target-avx2 \
  cargo test -p ic-ec -p ic-rsa -p ic-cipher -p ic-hash -p ic-mlkem
```

`--cfg ic_no_vaes` goes one step further for AES-GCM: it also turns off the
VAES detection, so the 256-bit kernel is skipped as well and the eight-block
AES-NI kernel that CPUs without VAES run (Skylake, Zen 2) is the default:

```bash
RUSTFLAGS="--cfg ic_no_avx512 --cfg ic_no_vaes" CARGO_TARGET_DIR=target-aesni \
  cargo test -p ic-cipher -p ironcrypto
```

The fused-kernel tests force every kernel the CPU has whatever the flags, so
these builds add that the specification vectors and Wycheproof run through
the narrower kernels as the default, and a test asserts which kernel is
chosen under each flag.

This is not a step in `scripts/check.sh`. It rebuilds the dependency graph
under different flags, a full build of several minutes, so it belongs in its
own target directory and a separate job if CI wants it. The benchmark
comparison that uses the same switch is in `docs/GRAVIOLA.md`.
