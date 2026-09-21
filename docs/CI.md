# Continuous integration

Four things gate this project, and they run the same script on purpose.

| where | what runs | when |
|---|---|---|
| `.githooks/pre-commit` | `scripts/check.sh --quick` | every commit |
| `.githooks/pre-push` | `scripts/check.sh` (adds cross-compilation) | every push |
| `.github/workflows/self-hosted.yml` | `scripts/check.sh` | every push, on a runner you provide |
| `.github/workflows/ci.yml` | the same gates, across three OSes and four targets | every push, on GitHub-hosted runners |

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
runner cannot: the three-OS matrix, the release-mode test run, and the four
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

The workflow installs the four
cross-compilation targets itself and prints the toolchain version before it
starts, so a machine that has drifted shows up in the log rather than quietly
producing a different answer from everyone else's.

### One thing to know before you register one

Anyone who can push to this repository, or open a pull request that runs this
workflow, runs code on that machine. For a private repository with a trusted set
of collaborators that is the normal arrangement. It is the reason GitHub advises
against self-hosted runners on *public* repositories, where a fork's pull request
would otherwise execute on your hardware. This repository is private; if that
ever changes, this workflow should be reconsidered at the same time.

Prefer a machine you do not mind rebuilding, and note that the runner keeps its
working directory between jobs, which is why the workflow points
`CARGO_TARGET_DIR` at the runner's temp directory rather than sharing a target
directory with whatever else is on the machine.

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
