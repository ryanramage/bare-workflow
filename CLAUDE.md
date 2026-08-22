# CLAUDE.md — internal notes and roadmap

Context for anyone (human or model) picking this up. The [README](README.md) is what the tool does;
[DEVELOPMENT.md](DEVELOPMENT.md) is how to work on it. This file is **why it is the way it is**, what
has already been measured, and what comes next.

Read the two sections marked **Do not relitigate** and **Measured findings** before proposing changes.
Most of the odd-looking code here exists because something else was tried and failed.

## What this is

A P2P build farm for Holepunch, on Bare. Ported in spirit from
[`wrkflw`](https://github.com/bahdotsh/wrkflw) (Rust, runs GitHub Actions locally), but not
GitHub-Actions-compatible.

The point was never "a CI runner". It is that a developer starting from
[hello-pear-bare](https://github.com/holepunchto/hello-pear-bare) can get from source to a **staged
Pear app**, safely, on hardware a team pools. Everything built so far — isolation, graph, artifacts,
offline installs, attestation, publishing — is infrastructure for that.

**Current state:** the whole single-machine path works. The real, unmodified `hello-pear-bare`
template cross-builds five of its six desktop targets from one Linux box, assembles a `by-arch/`
deployment folder, and stages it to a `pear://` link. ~290 tests / ~1200 asserts.

**Not built:** the farm itself (remote peers over hyperdht), real code signing, macOS and Windows
hosts, a TUI.

## Do not relitigate

These were decided deliberately, several of them by the user directly. Changing one is a real
decision, not a cleanup.

1. **Bare only.** No Node-only code paths in `lib/`. Use the `imports` map for `fs`/`path`/`events`/
   `subprocess` so modules load on both.
2. **Never emulation.** Explicit user instruction. No qemu-user, no binfmt, no cross-arch emulation
   tier — the risk of a subtly wrong build is worse than not building.
3. **No host-execution tier, ever.** A command allowlist over host processes is defeated by the first
   `sh -c`. It is not offered even as a fallback.
4. **Refuse rather than degrade.** If the available isolation is below the required minimum, exit 78
   and say what to install. Three reasons: failure is asymmetric (a build that did not run vs. an SSH
   key and a signing identity); silent degradation makes the tier attestation a lie, which destroys
   the farm's ability to reject weakly-built artifacts; and a silent fallback guarantees the strong
   tier is never exercised and rots.
5. **Isolation is top priority.** The user's words: "while no sandbox is perfect, lets choose the most
   airtight, secure for running an untrusted build. This is top priority." microVM is the default and
   the minimum for untrusted work.
6. **A native schema, not GHA compatibility.** No `uses:`, no remote action fetching, no expression
   language. This deletes wrkflw's entire action-resolution surface and a large attack surface with
   it. `toolchain:` replaces `uses:` with a curated, versioned image set.
7. **An unknown interpolation path is a hard error, never an empty string.** GHA's silent-empty-string
   is the single largest source of mystery CI failures. This is a headline feature, not a strictness
   tax.
8. **Nothing a build produces can widen its own sandbox.** Every `sandbox:`/`tier:`/`publish:` field
   is static and non-interpolatable, so `plan --json` is a complete reviewable contract before any
   untrusted code runs.
9. **Stop at staging.** No `provision`, `multisig` or `seed` driver. The docs say `pear stage` is for
   previews and staging, _not_ production; multisig exists so one compromised machine cannot redefine
   a release line, which a quorum of keys on one runner would defeat entirely; and `pear seed` is
   infrastructure that must outlive a build.
10. **The runner never mutates the developer's source.** `expect.upgrade` _asserts_ the link and fails
    on mismatch. It never writes it. This keeps the attestation describing exactly what was in the
    tree.
11. **Two affirmations to publish.** `dry-run: false` in the file _and_ `--publish` on the command
    line. A checked-in release workflow stays safe to run for any other purpose.
12. **The store takes a drive, not a path.** `localdrive` and `hyperdrive` share a surface, so the
    farm later passes a Hyperdrive and artifact return from a peer becomes `drive.mirror()`. This is
    the single highest-leverage decision for making the farm cheap.
13. **One repo, `lib/` subdirectories, no npm workspaces yet.** Eight `bare-*` repos before v1 is
    overhead while these boundaries are still moving. The two real extraction candidates when they
    settle are `bare-workflow-sandbox` and `bare-workflow-schema`.
14. **`js-yaml` is a starting point, not the destination.** It is the only YAML parser verified to work
    under Bare today. YAML parsing is confined to `lib/schema/` so replacing it is one swap. Its
    limitation: it gives positions for _syntax_ errors but not _semantic_ ones.

## Measured findings

Facts established by running something, not by reading. Each cost time to find.

### Capability is per-target, not per-platform

`bare-build` never compiles — it injects a bundle into a prebuilt runtime with `bare-lief`, and those
runtimes are ordinary npm packages with no `os`/`cpu` fields. So cross-_linking_ always works. The
only real constraint is a signature the host cannot issue.

| Target                 | From linux-x64                                       |
| ---------------------- | ---------------------------------------------------- |
| linux-x64, linux-arm64 | clean                                                |
| win32-x64, win32-arm64 | clean, unsigned (SmartScreen friction, not failure)  |
| darwin-x64             | clean — its runtime ships with no signature to break |
| **darwin-arm64**       | **builds a file that will not run**                  |

The darwin-arm64 failure is silent and was verified by parsing load commands:

|              | prebuilt runtime             | our build                                    |
| ------------ | ---------------------------- | -------------------------------------------- |
| darwin-arm64 | 20 cmds, `LC_CODE_SIGNATURE` | **21 cmds, signature present but now stale** |
| darwin-x64   | 19 cmds, none                | 20 cmds, none                                |

`lib/platform/apple/sign.js` in bare-build ad-hoc re-signs **only** when `os.platform() === 'darwin'`.
On Linux both branches are skipped with no warning. There is no hook for an alternative signer, so
`rcodesign`/`ldid` cannot be bolted in without patching bare-build.

So `lib/targets.js` reports a target as buildable unless it needs a signature this host cannot issue,
and records `unsignable` separately — a farm must distinguish "I cannot build this" from "I cannot
_sign_ this", because only the second is solved by routing to a Mac peer.

`android-arm64` is declined outright: its apk tooling ships prebuilds for only some hosts and this
was never verified. Declaring beats guessing.

### `--cap-drop ALL`, not seccomp, blocks nested-userns escalation

```
podman defaults:   unshare -Ur  ->  uid=0, CapEff: 000001ffffffffff
--cap-drop ALL:    unshare -Ur  ->  write failed /proc/self/uid_map: EPERM
```

A subagent originally claimed seccomp was doing this. It is not. Seccomp is defense-in-depth on top.

### tmpfs is charged to the memory cgroup

Writing 1500 MiB into a 4 GiB tmpfs under `--memory 1g` is **OOM-killed at ~1020 MiB**, not given
ENOSPC. So `tmpfs-size` is an upper bound the memory limit can make unreachable. The old defaults
(8 GiB workspace under a 4 GiB memory cap) promised a workspace twice the size of the fillable one
_and_ converted "disk full" into SIGKILL. `argv.resolveLimits()` now refuses an incoherent spec.

This also means the plan's original "unbounded podman volume" mitigation traded a disk-exhaustion
problem for an OOM-kill. The tmpfs is still the right choice; the sizes have to be coherent.

### `nofile: 4096` broke real builds with a misleading error

`bare-pack` traverses with unbounded concurrency (`concurrency` defaults to 0 — no semaphore) and its
`readModule` swallows every errno, returning `null`. A null read is indistinguishable from a missing
file, so **EMFILE surfaces as `MODULE_NOT_FOUND: Cannot find module 'b4a'`** for a module sitting
right there. Measured on the real template (140 packages): 330–593 EMFILE errors per build, a
different module named each run, ~2-in-3 failure rate. Now `nofile: 65536`.

Diagnosis path worth reusing: wrap `fs.readFile` via `node --require` and log every non-ENOENT errno.
Hypotheses rejected along the way — memory pressure (raising to 8 GiB changed nothing), krun
(container tier failed identically), and an incomplete npm tree (all 140 packages verified present).

### Node 18 silently fails exactly one target

`bare-addon-resolve` calls `Array.prototype.with()` (ES2023, node 20+) on the branch guarded by
`supportsUniversalPrebuilds(host)`, which is true for **darwin only**. Ubuntu 24.04 packages node
18.19.1, so `--host darwin-x64` died with `TypeError: conditions.with is not a function` while every
linux and win32 target built cleanly. `Containerfile.node` now installs node 22 from NodeSource and
asserts the capability at build time.

### The artifact store could not carry an executable

Three places flattened the mode: `lib/transfer.js` extracted every file `0o644` behind a comment
claiming it masked, and `lib/store/index.js` neither passed `executable` to `drive.put` nor read it
back on `get`. A distributable crosses the boundary six times on its way into `by-arch/`, so a green
run shipped a deployment folder of binaries nobody could run — failing only when a user
double-clicked.

Fixing it surfaced a second latent bug: `put` walked depth-first while `get` read drive keys
lexicographically, and those orders genuinely disagree (`a/b` vs `a.txt` — `.` sorts before `/`), so
the digests would never have matched once `get` started computing one. Both now use one
explicitly-sorted function.

**A stale baked agent reintroduces the mode bug invisibly**, because the agent bundles
`lib/transfer.js`. `test/support/lifecycle.js` asserts the round trip on both real tiers using
`test -x` from _inside_ rather than a mode we wrote ourselves.

### `--name` must equal `pkg.name`, and the failure is silent

`pear-runtime-updater` builds `/by-arch/${host}/app/${name}` from `pkg.productName || pkg.name`;
`pear-install` derives the installed binary name from `pkg.name`. `bare-build` runs `--name` through
a normalizer that lowercases and collapses non-alphanumerics. So `"name": "MyApp"` builds `my-app`
while the updater hunts for `MyApp` — `update not found`, long after CI went green.

### `pear stage` cannot run in a sandbox; `pear-ci` can run beside it

`pear/subsystems/sidecar/ops/stage.js` calls `sidecar.ready()` and
`sidecar.getCorestore({ writable: true })` — a long-lived sidecar owning a Corestore and a Hyperswarm,
plus a writable store. None of that belongs in an ephemeral `--network none` sandbox.

`pear-ci` is the org's own stateless alternative. Two things about it:

- **It cannot be `require`d on Bare as published.** All six of its dependencies ship an `imports`
  map; `pear-ci` itself ships none while requiring `fs` and `path`. Worked around at the load site
  with `bare-module`'s documented `imports` option (children inherit it). **A six-line PR upstream
  removes the workaround** — see Roadmap.
- **`stage()` waits for a peer and hangs forever with nothing seeding.** It polls
  `remoteContiguousLength` with no timeout and no output. Every publish is now raced against a
  deadline that reports the cause rather than the symptom.

The snapshot is durable state and load-bearing: two consecutive publishes with _fresh throwaway
storage_ produced `add` then `change` at the same link. Nothing but the snapshot prevents the second
run forking the drive.

### podman fails closed on an unreadable seccomp profile

Verified, because it matters for Windows:

```
$ podman run --security-opt seccomp=/nonexistent/profile.json ...
Error: opening seccomp profile failed: open /nonexistent/profile.json: no such file or directory
```

It **errors** rather than falling back to its permissive default. So a bad profile path is a loud
blocker, not a silent security regression. (A code audit flagged this as possibly the most dangerous
Windows finding; measurement says otherwise.)

### The first real macOS run: what only running it could find

Everything in this block was established on an Apple Silicon Mac (M1 Pro, Darwin 23.6.0, podman
5.4.2 applehv). The preceding commit ("macos prep") predicted macOS problems _from a Linux box_ and
got the reasonable ones right. These are the ones that needed hardware.

**An `undefined` env value is passed to the child as the literal string `"undefined"`.**
`bare-subprocess` builds the child environment with `` `${key}=${value}` `` over `Object.entries`.
`XDG_RUNTIME_DIR` is unset on macOS, so seven sites of the shape
`{ PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR }` shipped
`XDG_RUNTIME_DIR=undefined` and podman died before doing anything:
`Failed to obtain podman configuration: lstat undefined: no such file or directory`. This is a
**diagnosis trap**: podman worked perfectly, and `doctor` said "podman not found — install podman".
Allowlists are now built by _copying keys that are set_ (`lib/host-env.js`), never by naming them as
object literal properties, and the invariant "no value is the string `undefined`" is asserted.

**`podman version` cannot distinguish "not installed" from "machine stopped".** It exits 125 with
"Cannot connect to Podman" when the VM is down — which on macOS is the normal state of a correct
install. `detect.probe()` reported that as "podman not found". It now uses `podman info` (server-side
facts, as the roadmap already specified) and separates _missing_ / _not reachable_ / _misconfigured_,
each with a remediation that can actually be typed.

**`spawnSync` has no `timeout` option in `bare-subprocess`.** The word does not appear in the module.
`detect.js` passed `timeout: 30000` and it was inert on every platform, always had been. Removed
rather than left looking like a guard; there is no way to bound a _synchronous_ spawn from inside the
process, so a stalling podman would still hang. Not yet observed — do not build a watchdog for it
until it is.

**A caught missing-binary spawn still makes bare exit 144.** `spawn()` of an absent program throws
ENOENT, and even when that throw is caught the process exits 144 at teardown. So one spawn of a
binary that is not installed turns a fully green suite into a non-zero exit — and the thrown error
carries **no program name** (`no such file or directory`), which is also why the systemd-scope skip
guard, which matched on stderr text, missed and failed loudly instead. The rule now: look with
`which()` before spawning anything that might be absent. This is also why `bare scripts/build/agent.js`
exited 144 with no output at all when `bare-build` was not installed.

**`bare-os` has no `getuid`, so the escape suite's uid was always the literal 1000.**
`test/escape/index.js` computed `typeof os.getuid === 'function' ? os.getuid() : 1000`. The fallback
was always taken. Two consequences, and the second is the serious one:

- The negative control's `uid_map` assertion looked for a uid that is never mapped. That is how this
  was found — it failed on the Mac.
- The `podman_sock` probe tested `/run/user/1000/podman/podman.sock`, a path that exists only if your
  uid happens to be 1000. It reported `absent` in **both** postures, so the negative control never
  contradicted it — on _any_ machine with a different uid, Linux included. That is the `ip route`
  failure mode, on the probe that matters most, and it was never macOS-specific.

The uid and the socket path now come from `podman info` (`host.idMappings.uidmap`,
`host.remoteSocket`) — the machine where containers actually run, which on macOS is the VM's `core`
user (503 here), not this process. The environment test additionally asserts podman says the socket
_exists_, so "absent inside" is a measurement rather than a tautology. Honest remaining gap, measured:
bind-mounting the socket directory into the weakened container still reports absent, because
`/run/user/<uid>` is 0700 and the container user cannot traverse it even as container-root. So this
probe has no negative control; `any_socket` is what carries the teeth.

**`statfsSync('/home')` reports zero blocks on macOS.** `/home` is an autofs trigger (`map auto_home`).
The disk-exhaustion control computed a delta of 0 and its `< 64 MiB` assertion was trivially true. It
now picks a filesystem that reports real block counts and **fails** if none does. Verified live: a
200 MiB write moves the delta by exactly 209715200 bytes.

**`strayFds()` reported "clean" on any platform without procfs.** It enumerated `/proc/self/fd`
behind `catch {}` and returned `[]`, so "I looked and found nothing" and "I could not look" were the
same value — a security control that degrades to always-pass, which decision 4 exists to forbid. The
hello frame now carries `fdScan` (v5, append-only) saying whether the scan ran. Isolated tiers must
report `ok`; only the test-only local launcher may say it is inert, and it says so out loud.

**`file(1)` does not agree with itself across platforms.** For the same win32-arm64 binary Linux
prints `PE32+ executable (console) ARM64` and macOS prints `... Aarch64`. Pinning one spelling made
the cross-build test fail on a Mac while the artifact was perfectly correct.

**Two example lockfiles were gitignored, and both examples require them.** A blanket
`package-lock.json` rule excluded `examples/project/` and `examples/hello-pear/` — but
`examples/offline.yml` prefetches from the lockfile with no network, and its own comment says "the
committed lockfile". They worked on the machine they were written on because a stray `npm install`
had left them behind, and failed on the first fresh clone. Now explicitly un-ignored.

**The CLI reported an environment problem for a command-line typo.** Tier detection ran before graph
expansion, so a misspelled `--job` on a machine with no usable tier said "no isolation tier meeting
minimum 'microvm' is available" and exit 78. Static, host-independent checks (job selection, cycles,
`--env` parsing) now run first; the tier is still resolved before anything touches podman or runs a
step.

**The seccomp base profile is not the same file on every machine, and the differences bite.** The
generator hardens the container host's `containers-common` profile. Comparing an Arch host's base
against the Fedora CoreOS guest inside a macOS podman machine — 448 syscalls — **6 disagree**:

- `socket` with arg0 == 40 (**AF_VSOCK**) is denied via the Arch base and simply absent from the
  CoreOS one. AF_VSOCK is the host↔guest channel. Regenerating the profile on a Mac would have
  dropped that restriction silently.
- `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv` and `fanotify_init` are allowed by the
  Arch base and unlisted in the CoreOS one, so they would fall through to the default `ERRNO`.
  Denying the futex family with EPERM is the same hazard as the `clone3 → ENOSYS` case this
  generator's tests were written around — it breaks threading and presents as "npm hangs forever".

So "run the generator and commit the result" was only reproducible on the maintainer's distro, and
the drift guard was really testing which OS you were on. The base is now a **committed pin**
(`etc/seccomp/base-v1.json`) with `scripts/build/seccomp.js` to regenerate from it, `--check` to
detect staleness, and `--capture` as the deliberate, reviewable act of adopting a new upstream base.
The drift guard compares against the pin; a separate test still asserts the _live_ base has the
weakness the generator exists to fix, and that one now works on macOS by reading the base out of the
podman machine.

Note the committed profile itself was **not** regenerated — it is correct, and the escape suite plus
the new arch test confirm it denies what it should on arm64.

**The pin is now captured** (`etc/seccomp/base-v1.json`, from Arch `containers-common 1:0.69.1-1`,
the host that produced the committed profile). Two things were verified rather than assumed at
capture time: `bare scripts/build/seccomp.js --check` reports **up to date**, so the pin reproduces
the committed `build-v1.json` byte-for-byte — which is what proves the pin describes the real input
rather than merely being _a_ base; and the sha256 it generates, `ab8863e0a4b21cc4…`, is the one
already recorded in existing attestations, so nothing about the shipped posture moved. Both AF_VSOCK
bullets above were confirmed present in the captured pin and carried through to the output. The drift
guard now runs instead of skipping.

**Emulation is reachable on a Mac, and it defeats the guard meant to catch it.** A `podman machine`
on Apple Silicon registers a **`rosetta`** binfmt handler for x86-64 ELF (`interpreter /mnt/rosetta`)
plus **qemu-user handlers for ~31 other architectures**. There is no `qemu-x86_64` — Rosetta serves
that one. Measured: `podman run --platform linux/amd64 ubuntu:24.04 uname -m` prints `x86_64` and
exits 0. `podman machine set` has **no** `--rosetta` flag, so it cannot be turned off without a fresh
`init`, and the qemu handlers come from the CoreOS image and would survive that anyway.

Why this is a hard refusal rather than a warning: it is exactly the guard emulation defeats. An
x86-64 agent baked into an arm64 image is supposed to be a loud `exec format error` (podman exit 126) — under Rosetta it simply works, so the arch guard in `scripts/build/agent.js` reports success
for an emulated build, and the attestation records it identically to a native one. Decision 2 is
therefore enforced in code (`lib/isolation/arch.js`), not by machine configuration: configuration is
not a control, and a teammate's VM is not ours to configure. A related trap found in passing —
`podman pull --platform linux/amd64 ubuntu:24.04` **overwrites the tag**, so pulling once for a test
would silently make the whole escape suite run emulated.

#### Answers to the macOS blockers, now measured

- **Blocker 1 (agent architecture) is closed.** `scripts/build/agent.js` read `arm64` from the podman
  server, cross-built an `ELF ARM aarch64` agent, and it executes in the guest. No `exec format
error`, no exit 126.
- **Blocker 3 (seccomp path) is real but much narrower than expected.** podman machine mounts **both
  `/Users` and `/private`** via virtiofs, so a checkout under either resolves in the guest — measured
  from `/private/tmp` as well as from `$HOME`. `/Volumes` is _not_ mounted and fails with
  `Error: opening seccomp profile failed: ... no such file or directory`. So it fails **closed and
  loudly**, consistent with the Linux measurement. The launcher now explains that error instead of
  naming a host path that plainly exists.
- **Blocker 4 (x86-only seccomp architectures) is NOT a hole.** Measured by isolating seccomp from
  `--cap-drop`: with **full capabilities** and the profile, `unshare` returns EPERM and `mount` fails;
  with full capabilities and `seccomp=unconfined`, both succeed. So the filter applies on aarch64
  even though the profile declares only `SCMP_ARCH_X86_64/X86/X32` — `seccomp_init()` installs the
  native arch and `architectures` only ADDS to it. The x86-only syscall _names_ (`modify_ldt`,
  `iopl`, `ioperm`, `arch_prctl`) do not stop the container starting: ordinary tools still run. This
  is now a regression test with its own built-in control, in `test/argv-runs.js`.
- **Blocker 2 (every default `run` exits 78) still holds, and is now correct.** `minTier` defaults to
  microvm, krun is permanently unreachable on macOS, so `--tier container` is required. What changed
  is that it is reached for the right reason and says so. Note the consequence for tests: any test
  asserting exit 78 for some _other_ cause must pass `--tier` explicitly, or it passes for the wrong
  reason.

### Other findings not worth relearning

- Under krun the guest has full capabilities **by design** — the VM is the boundary. Escape assertions
  must be tier-aware or they are simply wrong tests.
- The negative control has already caught a false pass: a probe used `ip route`, absent from
  `ubuntu:24.04`, so _both_ postures reported zero routes.
- A tmpfs workspace needs `tmpfs-mode=1777` **and** `--workdir` pointing inside it, because podman
  creates the workdir as root before dropping privileges. Both failures show `pwd` working and only
  writes failing.
- `require(someVariable)` is invisible to bare-build's bundler, so an "optional" dependency simply is
  not in the binary.
- hrpc's append-only guarantee protects the _encoding_, not the _call_.
- `prefetch: [npm]` must default to prod-only: the template's `bare-build` devDependency pulls 13
  prebuilt runtimes (~1 GB), taking the plan from 1 package to 61. `npm-dev` is the opt-in — and note
  it currently OOMs on the real template, since ~1 GB of runtimes extracted into a tmpfs exceeds the
  memory cap.
- `npm ci` in the sandbox emits `TAR_ENTRY_ERROR EPERM: fchown` warnings. Expected and benign under
  `--cap-drop ALL`; the install completes correctly.

## Roadmap

**macOS is the next target**, ahead of Windows. It is the bigger prize: a Mac is the only host that
can produce `darwin-arm64`, which is the one gap a Linux runner cannot close. Windows adds `signtool`
and native Windows tests, but nothing that is currently impossible.

macOS is also _closer_ than the Windows notes further down suggest. The three worst Windows findings
— the destroyed execute bit, the unusable config permission check, and `SIGTERM` not being forwarded
— **do not apply to macOS at all**, because macOS has real POSIX modes and real signals. Publishing
needs no changes there.

### macOS host support

#### The shape of the work: a Mac has two unrelated roles

This is the thing to understand before writing any code, because it means macOS support is _not_
"port the podman driver".

1. **A Linux-container peer.** `podman machine` on macOS runs an applehv Linux VM; containers inside
   are Linux containers. This works roughly as it does today and builds linux, win32 and darwin-x64.
   **It adds nothing we do not already have** — and critically, it _cannot_ build `darwin-arm64`,
   because `codesign` does not exist in a Linux guest.
2. **A native darwin builder.** Running `bare-build --host darwin-arm64` on macOS itself, so
   `codesign` can run. **This is the gap**, and it cannot use the podman path at all.

So closing the gap means adding a **second, different execution tier**, not fixing the existing one.

#### The good news: a runnable darwin-arm64 needs only ad-hoc signing

Read from `bare-build`'s `lib/platform/apple/sign.js`. With no `--sign` flag it runs:

```js
} else if (os.platform() === 'darwin') {
  await run('codesign', ['--timestamp=none', '--force', '--sign', '-', resource])
}
```

That is an **ad-hoc signature**, and it is all Apple Silicon requires to _execute_ a binary. So
producing a working `darwin-arm64` distributable needs **`codesign` from the Xcode Command Line Tools
and nothing else** — no developer certificate, no Apple ID, no keychain, no notarization. The
template's `make:darwin-arm64` script passes no `--sign`, so it already takes this path.

That is a far lower bar than "implement signing", and it means the Mac can close the real gap almost
immediately. Real signing — `--sign` with an identity, entitlements, hardened runtime, notarization —
stays a separate, later problem. Ad-hoc binaries still get Gatekeeper quarantine on _download_; how
much that matters depends on whether Pear's own updater writes the file directly rather than via a
browser, which is worth checking rather than assuming.

#### Blocker 1: the baked agent is x86-64 and an Apple Silicon podman machine is arm64

**This corrects a claim in the Windows section below**, which said "the baked agent stays `linux-x64`
… nothing assumes host platform == container platform, which was verified by audit." That is right
about the _platform_ and wrong about the _architecture_. Verified here: `ubuntu:24.04` publishes a
`linux/arm64` manifest, and `out/agent/bw-agent` is `ELF 64-bit LSB pie executable, x86-64`. Inside
an arm64 podman machine, `FROM ubuntu:24.04` resolves to arm64 and the x86-64 agent is an
`exec format error` at `--entrypoint /opt/bw/agent` — surfacing as `podman exited 126`, which reads
as a launcher bug rather than an architecture one.

Note that the _easy_ fix — enabling Rosetta or qemu in the machine — is exactly what decision 2
forbids. **Already fixed** instead: `scripts/build/agent.js` now reads the arch from the podman
**server** (`podman info --format {{.Host.Arch}}`), defaults `--host` from it, and refuses a mismatch
before spending a minute on the build. Measured on this Linux box: the arm64 agent cross-builds fine
(`ELF … ARM aarch64`), so the Mac's agent can be produced anywhere.

`--cross` builds the binary and **stops**, deliberately not producing an image: `FROM ubuntu:24.04`
resolves to the build host's arch, so an x64 machine would emit x64 Ubuntu layers with an arm64 agent
inside — an image that runs on neither side. Making it genuinely arm64 needs `--platform`, and the
Containerfile has `RUN` steps, so that needs emulation. Carry the binary over and run
`bare scripts/build/agent.js --skip-binary` on the Mac.

#### Blocker 2: every default `run` exits 78, and the tier question has a firmer answer here

`minTier` defaults to `microvm`, and krun is unreachable on macOS — permanently. applehv guests get
no `/dev/kvm`, and Apple Silicon nested virtualisation needs M3+ and is not exposed by podman
machine. There is no path to krun-in-a-podman-machine on a Mac at all.

**Partly fixed:** `detect.probe()` is now platform-aware and no longer tells a Mac user to run
`pacman -S libkrun libkrunfw`. It says krun is Linux-only and names the real trade-off.

**The decision still open** — and it is yours, not a cleanup: containers inside a podman machine are
already nested in a VM, so the host boundary _is_ a VM boundary. But it is **shared across every
job**, unlike krun where each job gets its own. That is a genuinely different security property and
probably deserves its own tier name and rank rather than being folded into `container` (which
understates it) or `microvm` (which overstates it). Whatever it is called, probe it with
`podman info` — server-side facts — not host filesystem checks, so a _stopped_ machine is also
diagnosed.

#### Blocker 3: the seccomp profile path, and why it is sneakier on a Mac

`bin.js` resolves `etc/seccomp/build-v1.json` to an absolute host path, and the podman service inside
the VM reads that path off _its own_ filesystem. On Windows it is an obviously-wrong `C:\...`; on
macOS it is a plausible POSIX path that fails anyway. podman **errors** rather than falling back
(measured — see Measured findings), so this is loud.

**Worth measuring before designing the fix:** podman machine on macOS bind-mounts `$HOME` into the VM
by default. If the repo lives under `$HOME` the same absolute path may actually resolve inside the
guest, so this blocker _disappears_ for developers with the repo in `~/` and appears for anyone with
it under `/opt` or `/Volumes`. A bug that depends on where you cloned is worse than a clean break.

Related: `seccomp.js`'s `BASE_PATH = '/usr/share/containers/seccomp.json'` lives in the VM, so the
generator cannot run on macOS. `generate()` already accepts `opts.base`/`opts.basePath`, so wiring a
CLI flag and pulling the base out with `podman machine ssh cat` is enough.

#### Blocker 4: the committed seccomp profile declares only x86 architectures

`etc/seccomp/build-v1.json` lists `SCMP_ARCH_X86_64`, `SCMP_ARCH_X86`, `SCMP_ARCH_X32` and no
`SCMP_ARCH_AARCH64`. Reading libseccomp suggests `seccomp_init()` always installs the native arch, so
the filter probably still applies and this is probably not a hole — but **measure it, do not reason
about it**. Two audits have now been wrong about seccomp in this project. Run the escape suite's
`unshare`/`mount` probes on an arm64 guest and confirm they still report blocked. Secondary: the
x86-only syscall names (`modify_ldt`, `iopl`, `ioperm`, `arch_prctl`) resolve to `-EDOM` on aarch64,
and whether crun skips or errors determines if the container starts at all.

#### Fixed while preparing

- **Capability followed the host OS, not where the job runs.** `describe()` used `os.platform()`, so a
  Mac would have claimed `darwin-arm64` and then built it in a Linux container — producing exactly the
  dead binary the model exists to refuse. Now derived from `TIER_PLATFORM`; adding a darwin tier there
  is what legitimately unlocks `darwin-arm64`. The attestation records `platform` **and**
  `execPlatform`, because "built on macOS" and "built in a Linux guest on a macOS host" imply
  different things about signatures.
- **The empty-tier fallback** (podman missing, or machine stopped) fell back to the host, which on a
  Mac re-created the same over-claim in `validate` and `doctor`. It now answers with the platform this
  runner's tiers execute on.
- **Two test probes hardcoded a POSIX `PATH`** without `/opt/homebrew/bin`, so on Apple Silicon the
  escape suite _and its negative control_ would have gone silently vacuous — while working on an Intel
  Mac. Nastier than the Windows version for being machine-dependent.
- **Two kernel-difference checks were vacuous.** `test/argv-runs.js` matched the literal string
  `cachyos` (the developer's distro), and `test/cli.js` compared against `os.version()` — the build
  banner — instead of `os.release()`, so `includes()` could never be true. A guest kernel identical to
  the host's would have passed both. The audit reported cli.js as the correct example to copy; it was
  not.
- **An unguarded `evs.find(...).data`** turned one failing test into an uncaught TypeError that killed
  the whole suite at test 236 of 290. There is now a `need()` helper.

#### Still to do, in order

Items 1, 2, 3, 4 and 6 of this list are **done** — see "The first real macOS run" above for what each
one actually turned out to be. The state now: the whole suite runs on macOS and the container tier is
real. `hello-pear-bare` cross-builds all five buildable desktop targets from this Mac, in a Linux
guest, and stages to a `pear://` link.

What remains:

1. ~~**The shared-VM tier decision.**~~ **Decided and built.** It is the **`machine`** tier, rank
   **70** — between `container` (50) and `microvm` (90). The probe asks `podman info` for
   `Host.ServiceIsRemote` rather than testing `os.platform()`, so a Linux user running a podman
   machine gets the same answer a Mac user does, and a genuinely remote podman host does too. The
   attestation records `isolation.shared` alongside the tier name, because a shared podman-machine VM
   and a dedicated remote builder both report `machine` and are not the same promise.

   The default minimum stays `microvm`, so **macOS still needs an explicit `--tier machine`** — no
   default anywhere got weaker. `TIER_PLATFORM.machine = 'linux'`, which is what keeps `darwin-arm64`
   correctly refused; there is a test asserting exactly that, because "we have a stronger tier on
   macOS now" is a tempting and completely wrong reason to think a Mac can build its own platform.

2. ~~**The macOS setup story.**~~ **Done.** `detect.setupChecks()` returns records for all three and
   `doctor` renders them under `setup`. Each is **tri-state**: `ok: null` means "could not tell",
   which is deliberately not the same as passing. Two details worth keeping:

   - The memory requirement is derived from `argv.resolveLimits()` rather than written down, so it
     cannot drift from what a run actually asks for.
   - The advice asks for **more** than the shortfall. A machine created with `--memory 8192` reports
     ~7.73 GiB to containers, so advising exactly the requirement produces the worst kind of
     remediation: one that tells you to set the value you already set. Found by the check firing on
     the very machine that had just been resized to satisfy it.

3. ~~**Rosetta.**~~ **Enforced in code instead of configuration** — see the emulation finding above.
   `lib/isolation/arch.js` refuses any image whose architecture is not the runtime's, before anything
   runs, with exit 78 and a message that names both architectures and the mechanism. Rosetta is
   deliberately left enabled: the refusal holds on any machine however it was created, including a
   teammate's, which configuration never could.
4. **`resolveLimits()` still does not check the machine's real capacity itself.** `doctor` now does
   (item 2), which is where a human sees it — but a `run` will still accept an 8 GiB cap on a 2 GiB
   machine and OOM the VM rather than the job. Wiring the same server-side fact into the run preflight
   is the remaining half.
5. **Then the actual goal:** a darwin execution tier, so `darwin-arm64` can be built. See below.

#### The darwin execution tier: three options, and a decision you need to make

There is **no container option** for `darwin-arm64`. The choices:

| Option                                                                      | Isolation                            | Cost                                                            | Notes                                                                                                                                                                                                                                                                  |
| --------------------------------------------------------------------------- | ------------------------------------ | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **macOS VM per job** (`tart`, `lume`, or Virtualization.framework directly) | Strong — a real guest OS             | High: a guest image with Xcode CLT, a darwin agent, a data path | Apple's EULA permits **2 concurrent macOS VMs per host**, which is a hard cap on farm throughput. `tart` is source-available under a fair.dev licence — free for personal/OSS, commercial use needs sponsorship above a revenue threshold. Check that before adopting. |
| **`sandbox-exec` (Seatbelt)**                                               | Moderate — same kernel, SBPL profile | Medium                                                          | Officially deprecated since 10.14 but fully functional, and used in production by Bazel's darwin sandbox and by Nix for exactly this purpose. Credible, and far better than nothing.                                                                                   |
| **Native, trusted-key-only**                                                | None                                 | Low                                                             | Honest interim.                                                                                                                                                                                                                                                        |

**The tension you should decide, not me.** Decision 3 says "no host-execution tier, ever", and the
third option is host execution — `lib/agent/index.js` runs `sh -c`, which is precisely what that
decision names. `test/support/local-launcher.js` exists under `test/` specifically so there is no code
path from a workflow to it, and promoting it to `lib/` is a reversal rather than a port.

The argument _for_ allowing it, which you may or may not accept: this codebase already has a trusted,
unsandboxed execution path — a `publish:` job runs on the runner holding the key — so "trusted work
runs outside the sandbox" is an established pattern here rather than a new concession. And
`darwin-arm64` _inherently_ requires signing, which is already trusted-key-only, so darwin-arm64 is
arguably trusted-only by construction until a VM tier exists.

The argument _against_: a build is exactly the thing you do not trust, and "trusted key" is a much
weaker guarantee for arbitrary build scripts than for a single `pear-ci` call with no user code in it.

**Decided: `sandbox-exec` first.** It is a real boundary, it needs no VM image, no licensing question
and no EULA cap, it keeps decision 3 intact in spirit, and Bazel and Nix have both proven it viable
for sandboxed builds. A VM tier can come later for genuinely untrusted work.

##### The premise is no longer a theory — it is measured

Four things were verified on the Apple Silicon box before writing any of the plan below, because the
whole tier is pointless if any of them is false:

| Question                                                        | Measured answer                                                                        |
| --------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Does a native `darwin-arm64` build produce a **runnable** file? | **Yes.** `Mach-O 64-bit executable arm64`, `Signature=adhoc`, `flags=0x2(adhoc)`, runs |
| Is a certificate or Apple ID needed?                            | **No.** Xcode CLT `codesign` alone; the template passes no `--sign`                    |
| Does `codesign` still work **inside** `sandbox-exec`?           | **Yes.** Same ad-hoc signature, same running binary, built under a Seatbelt profile    |
| Does Seatbelt actually deny anything?                           | **Yes.** `cat ~/.ssh/id_ed25519` → `Operation not permitted` under a `deny file-read*` |

That last pair is the crux and the reason to stop worrying about this approach: signing works under
Seatbelt _and_ Seatbelt keeps the build out of the host's secrets, simultaneously. `sandbox-exec` is
also formally deprecated (since 10.14) and entirely functional — that tension is real but Nix and
Bazel both ship on it, and the deprecation has outlived several macOS majors.

##### What has to be built

1. **`TIER_PLATFORM.darwin_native = 'darwin'`** (name it whatever) in `lib/targets.js`. This single
   entry is what legitimately makes `buildableOn('darwin', 'darwin-arm64')` true, and it must be
   added **only** together with the rest — on its own it makes the runner claim a capability it has
   no way to execute, which is precisely the dead-binary failure the model exists to refuse.
2. **A probe and rank in `detect.js`.** The probe is cheap and should assert all three of
   `sandbox-exec`, `codesign` and a usable Xcode CLT (`xcode-select -p`) rather than just the first,
   since a machine with `sandbox-exec` and no CLT would fail late and confusingly. Rank it **below
   `machine` (70)**: same-kernel confinement is weaker than a separate machine. Somewhere near 40 is
   honest — it is not a container either, and pretending otherwise repeats the mistake `machine` was
   added to fix.
3. **Its own limits vocabulary.** `argv.js` is entirely podman-flag-shaped and does not transfer:
   there is no `--memory`, no `--pids-limit`, no `--userns` and no tmpfs. The analogues are `ulimit`,
   a `TMPDIR` inside a per-job scratch directory, and an SBPL profile — and several podman limits have
   **no** analogue at all. Say which ones are unenforceable in the attestation rather than emitting a
   limits record that implies they were applied.
4. **The SBPL profile, generated the way the seccomp profile is.** Same shape as
   `lib/isolation/podman/seccomp.js`: a pure function producing a reviewable document, a committed
   output, and a drift guard. Start from `(deny default)` and allow, not the reverse — the probe above
   used `(allow default)` because it was only testing whether `codesign` survives confinement, and
   that posture is **not** a sandbox.
5. **`strayFds()` must gain a darwin backend first.** It is `/proc`-only, and this session made it
   _report_ that honestly rather than silently returning `[]` — but "honestly unsupported" is fine for
   a test-only local launcher and not fine for a real tier. A native tier whose fd-leak detector
   cannot run is a security control that does not exist. This is a prerequisite, not a follow-up.

##### The decision-3 tension, restated now that the facts are in

Decision 3 says "no host-execution tier, ever", and `sandbox-exec` runs on the host kernel. The
distinction that makes this a port rather than a reversal: decision 3's actual argument is that "a
command allowlist over host processes is defeated by the first `sh -c`". A Seatbelt profile is not a
command allowlist — it is kernel-enforced MAC that applies to `sh -c` and everything it spawns, which
is exactly what the measurement above demonstrates. What decision 3 forbids is
`test/support/local-launcher.js` promoted to `lib/`, i.e. **unconfined** host execution. That remains
forbidden, and this tier must not become a route to it: if the Seatbelt profile fails to load, the
tier is unavailable and the run refuses. It must never fall back to running unconfined.

### After macOS

### Windows host support

A Windows host adds `signtool` and native Windows testing. Everything below still holds **except the
agent-architecture claim, corrected in the macOS section above** — on WSL2-x64 an `linux-x64` agent is
right, which is why the error was not caught; on Apple Silicon it is not.

Setup on the Windows machine: `winget install RedHat.Podman`, then `podman machine init` and
`podman machine start`. Note what this means architecturally — **podman on Windows is a remote
client** talking to a service inside a WSL2 Linux VM. Containers are Linux containers. So:

- The baked agent is `linux-x64`, which happens to be right here because a WSL2 machine on an x64
  host is x64. **This was originally written as "nothing assumes host platform == container platform"
  — true of the platform, false of the ARCHITECTURE**, and it is wrong on Apple Silicon. See the macOS
  section. `scripts/build/agent.js` now derives the arch from the podman server, so this is handled;
  the lesson is that "the container is always Linux" is only half the invariant.
- You do **not** need Windows to build `win32-*` targets — that already works from Linux. What Windows
  unlocks is real code signing and native Windows test execution.
- The container-side flags all survive, because the server in the VM interprets them. None of the
  flags `argv.js` emits are documented as remote-unsupported.

The findings below come from a **code audit, not from running on Windows**. Treat them as a checklist
to verify, not as established fact. Where something was actually measured it says so.

#### Hard blockers, in the order they will bite

1. **The spawn env allowlist is POSIX-only.** Five sites forward only `PATH`/`HOME`/`XDG_*`:
   `lib/isolation/detect.js:38`, `bin.js:76` and `:419`, `scripts/build/agent.js:32`, and
   `requiredHostEnv()` in `lib/isolation/podman/argv.js`. `podman.exe` needs `USERPROFILE`, `APPDATA`,
   `LOCALAPPDATA` (where `containers.conf` and the machine connection database live), plus
   `SystemRoot` and `TEMP`. `HOME` is normally unset on Windows so the fallback never fires.

   The symptom is a **diagnosis trap**: podman works fine, and `doctor` reports "podman not found —
   install podman". Fix this first or every other finding is masked. Also note `requiredHostEnv`
   defaults `PATH` to `/usr/local/bin:/usr/bin:/bin`, which resolves nothing on Windows.

2. **`lib/config.js`'s permission check can never pass.** libuv synthesizes `st_mode` on Windows from
   file attributes: writable → `0666`, read-only → `0444`. So `stat.mode & 0o077` is always truthy and
   the check always fails, printing a `chmod 600` remediation that cannot be followed. Every workflow
   with a `publish:` job dies at preflight.

   **Do not silently skip this.** It guards a private key. The options are a real ACL check
   (`icacls`) or an explicit, loud "cannot verify file permissions on this platform" refusal with an
   opt-out flag. A silent skip is the one unacceptable answer.

3. **The seccomp profile path is a Windows path handed to a Linux server.** `bin.js:26` resolves
   `etc/seccomp/build-v1.json` to `C:\...`, and the podman service reads that path off _its_
   filesystem inside the VM. Measured on Linux: podman **errors** rather than falling back, so this
   fails loudly. Same class: `seccomp.js`'s `BASE_PATH = '/usr/share/containers/seccomp.json'` lives
   in the VM, so the generator cannot run on Windows at all.

   The likely fix is to ship the profile into the machine (or a volume the service can read) and pass
   the in-VM path.

4. **Tier probing asks the wrong machine.** `detect.js` checks the _host_ for `crun`, `libkrun.so` and
   `/dev/kvm`. On Windows those resolve to `C:\usr\lib\...` and `C:\dev\kvm` and all fail — which is
   accidentally the right answer for the wrong reason. The real question is whether the **podman
   machine VM** has them, and a stock machine image has neither. So the microvm tier is genuinely
   unreachable, and since `minTier` defaults to `microvm`, every default `run` exits 78.

   This needs a design decision, not just a fix. A defensible position: containers inside a podman
   machine are already nested in a VM, so the host boundary _is_ a VM boundary — but it is **shared
   across all jobs**, unlike krun where each job gets its own. That is a genuinely different security
   property and deserves its own tier name and rank rather than being folded into either existing one.
   Probe it via `podman info` (server-side facts), not host filesystem checks.

5. **`systemd-run` is still the default `program` in `argv.build()`.** The CLI hardcodes
   `scope: false` (`bin.js`), so this only bites library consumers — but `./isolation/podman/argv` is
   a public export and the _safe_ value is the non-default one. Worth inverting.

6. **`scripts/build/agent.js` cannot run on Windows.** `bare-build` is a `.cmd` shim there, and
   libuv's spawn path search only tries `.com`/`.exe` — it does not consult `PATHEXT`. Build the agent
   on Linux and copy it, or spawn through `cmd /c`.

7. **`lib/publish/pear-ci.js` builds a file URL by string concatenation** —
   `new URL('file://' + __dirname + '/')` — which breaks on `C:\...`. Needs `pathToFileURL`.

#### Silent wrongness — fix before trusting a Windows run

1. **The execute bit is destroyed in both directions.** On Windows `stat.mode` is `0666`, so
   `transfer.js`'s pack (`stat.mode & 0o755`) yields `0644` and nothing checked into a repo can arrive
   executable inside the container. Outbound, `writeFileSync`'s mode is ignored, so
   `!!(stat.mode & 0o100)` is false for **every** artifact and every published distributable lands
   non-executable. This is exactly the failure the store was fixed to prevent, and it also silently
   changes the artifact digest — the same build produces a different digest on a Windows host.

   **Windows publishing should probably be blocked outright until this is resolved.** The mode has to
   come from somewhere other than the host filesystem: carry it in the workflow, or derive it from the
   tar the sandbox produced.

2. **The container and escape test suites silently skip.** `test/escape/harness.js:39` and
   `test/argv-runs.js:27` default their spawn env to a hardcoded POSIX `PATH`, so podman is
   unresolvable, every probe reports "podman unavailable", and the whole escape suite plus its
   negative control go green while measuring nothing. Given that the negative control is the reason to
   trust any of it, fix these two lines before drawing conclusions from a Windows test run.

3. **tmpfs sizes are measured against the WSL VM's RAM, not the host's.** A podman machine typically
   gets 50% of host RAM or 8 GB, whichever is smaller, and is configurable separately in `.wslconfig`.
   The current defaults (4 GiB workspace + 1 GiB `/tmp` + 8 GiB memory cap) can OOM the _VM_ rather
   than the job, presenting as an unexplained container death or a hung client.

4. **`proc.kill('SIGTERM')` is `TerminateProcess` on Windows** and is not forwarded to the container,
   so the first two rungs of the cancellation ladder collapse. The `podman rm -f` reaper is what
   actually stops things — and it inherits the broken env from blocker 1, so there is a real risk of
   orphaned containers left running in the VM after a cancel.

5. **`XDG_CONFIG_HOME` is rejected if it does not start with `/`** (`lib/config.js`), silently falling
   back to `%USERPROFILE%\.config` — workable, but not where a Windows user would look, and the error
   text gives no hint.

#### Test-only

Tests that will _fail_ rather than skip: `test/agent.js` (shell resolution expects `/bin/sh`;
`/etc/hostname`; `/proc/self/fd`), `test/store.js` and `test/transfer.js` (POSIX mode semantics and
`symlinkSync`, which needs admin or Developer Mode), `test/escape/exhaustion.js`
(`statfsSync('/home')`), `test/escape/harness.js` (`plantCanary` writes to `$HOME`), and
`test/support/lifecycle.js` / `launchers.js` (`cwd: '/tmp'`, mode assertions).

There is a large amount of hardcoded `/tmp/` in test scratch paths. A shared `tmpdir()` helper is the
right fix rather than patching each site.

One unrelated bug found while auditing: `test/argv-runs.js:118` asserts the guest kernel differs from
the host by matching the string `'cachyos'` — the current developer's distro. It is vacuous anywhere
else. `test/cli.js` does the same check correctly via `os.version()`; copy that.

#### Suggested order

1. Env allowlist (blocker 1) — nothing else is diagnosable until this works.
2. The two test probe defaults (silent 2) — so a test run means something.
3. `detect.js` probing via `podman info`, and decide the shared-VM tier question (blocker 4).
4. The seccomp path (blocker 3).
5. The config permission check (blocker 2), then the exec bit (silent 1), then unblock publishing.

- **macOS host.** The bigger prize, because it is the only thing that can produce `darwin-arm64`.
  Needs a real ephemeral VM tier (`tart` / Virtualization.framework — check licensing). No container
  story exists on macOS at all.
- **The farm.** `lib/peer/{local,remote}.js` is the intended seam. A `Task` is already a plain
  serializable object and the runner takes `(task, driver, store)`, so remote dispatch is meant to be
  "JSON over hrpc, NDJSON events back" with no runner changes. Capability matching falls out of
  `targets:` already meaning "needs a machine that can build this". Authorization is an explicit
  allowlist of trusted public keys (deferred, decided).
- **Signing.** Design against the _oracle_, not just the theft: stealing a P12 is loud and revocable,
  but getting your Developer ID to sign an attacker's Mach-O is quiet and attributed to you. The
  runner (never the build) should send `SignRequest{artifacts[], appId, attestation}` to a signer on a
  separate machine that independently parses the binary, rate-limits per key, and appends to a
  transparency log. Entitlements, bundle id and identity are **server-side policy keyed by an
  allowlisted bundle id**, never passed through from a workflow.

  Cost is asymmetric: **Windows is nearly free** (`WINDOWS_SIGN_HOOK` is already a pluggable JS
  module), **macOS is the single largest piece of new work** because `codesign` is invoked
  inner-binaries-first deep inside packaging, so the signer must own macOS packaging end to end. Do
  Windows first to prove the architecture.

- **Upstream PRs worth sending.** (a) `pear-ci`: add an `imports` map for `fs` and `path` — six lines,
  removes our load-site workaround entirely. (b) `bare-pack`: stop swallowing errno in `readModule`,
  and default `concurrency` to something bounded. (c) `bare-build`: a hook for an alternative Mach-O
  signer would let a Linux host produce a usable `darwin-arm64`.
- **Smaller, known gaps.** The real dependency set is now exercised by the template build, but
  `prefetch: [npm-dev]` OOMs on it. Cache save/restore between runs does not exist. Free-form
  `matrix:` axes beyond `targets:` are not implemented. `linux-arm64` as a _host_ is untested.
  Replacing `js-yaml` with our own parser is intended (see decision 14).

## Working style notes

Things that have gone wrong in this project's own development, worth avoiding:

- **Verify subagent and audit claims before acting on them.** One audit called seccomp the thing
  blocking userns escalation (it is `--cap-drop ALL`); another called an unreadable seccomp profile a
  probable silent fallback (podman errors). Both were plausible and wrong. Measure.
- **Assert on records, not on log output.** Two bugs during development were introduced by Prettier
  reformatting a patch target, and both were caught only by tests that assert on structured records
  while the logs looked fine.
- **A green suite can mean nothing.** The negative control exists because of this. When adding a
  security test, also make it fail against the weakened provider.
- **Round-trip the branch between machines before believing it.** Bringing the macOS branch back to
  Linux caught two things a single-machine run could not. (a) A stale baked agent: `out/` is
  gitignored, so a checkout that changes `lib/agent/` leaves a binary older than its source — the
  handshake reported `unknown: agent predates the fdScan field`, which only surfaced cleanly because
  that field is explicitly version-checked. (b) A test made host-dependent by a blanket fix: adding
  `--tier can.tier` to every run test so macOS would not exit 78 was right everywhere except the one
  test asserting that a workflow's `tier:` declaration is honoured — `--tier` is precisely the
  override that supersedes it, so the test passed on a Mac (where `can.tier` IS `container`) and
  failed on Linux (where it is `microvm`). A blanket fix applied to a test suite deserves a check for
  the one test whose subject is the thing being blanket-fixed.
- **The hello-pear publish job flakes under full-suite load.** Observed twice on macOS: the run exits
  1 with no `publish/done` event, while the same test passes in isolation. Not diagnosed — the likely
  candidate is pear-ci's 120 s deadline (`DEFAULT_TIMEOUT_MS`), which is a wall-clock race against a
  local DHT peer replicating, on a machine simultaneously running containers for five build targets.
  Two things were done rather than pretending it is fixed: the test now surfaces the
  `publish/error` reason in the same run, and every read of the publish record is guarded so a
  missing one **fails** instead of throwing an uncaught ENOENT that kills the suite and reports the
  failure against whatever test happened to be last. If it recurs, the reason will now be in the
  output.
- **Rebuild the agent and every layered image** after touching anything in `lib/` that the agent
  bundles. The in-sandbox half of a change otherwise silently does not exist.
