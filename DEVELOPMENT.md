# Developing bare-workflow

For working _on_ the runner. If you want to _use_ it, start with the [README](README.md).

## Setup

```bash
npm install

bare scripts/build/agent.js                                                               # agent + base image
podman build -f etc/Containerfile.node       -t localhost/bare-workflow-node:dev .        # node 22
podman build -f etc/Containerfile.bare-build -t localhost/bare-workflow-bare-build:dev .  # + bare-build
podman build -f etc/Containerfile.pear       -t localhost/bare-workflow-pear:dev .        # + pear-build

npm test
npm run lint
npm run build:rpc   # regenerate schema/spec from schema/builder (committed output)
npm run build:seccomp   # regenerate etc/seccomp/build-v1.json from the pinned base
```

### The seccomp profile is generated from a PINNED base

`etc/seccomp/build-v1.json` is produced by hardening the container host's `containers-common`
profile — and that input differs between distros in ways that are not cosmetic. Measured across 448
syscalls, an Arch host and the Fedora CoreOS guest in a macOS podman machine disagree on 6: the Arch
base denies `socket(AF_VSOCK)` (the host↔guest channel) and the CoreOS one does not, and CoreOS omits
the `futex_*` family so it would fall through to a default EPERM — the same class of breakage as the
`clone3 → ENOSYS` bug the tests were written around.

So the base is committed as `etc/seccomp/base-v1.json` and the generator reads that, not your
machine. The drift guard in `test/seccomp.js` compares against the pin, which makes it mean "someone
changed the generator without regenerating" rather than "you are on a different distro".

```bash
bare scripts/build/seccomp.js            # regenerate the profile from the pinned base
bare scripts/build/seccomp.js --check    # exit 1 if the committed profile is stale
bare scripts/build/seccomp.js --capture  # adopt a NEW upstream base -- review this diff carefully
```

`bare-build` must be on PATH (`npm i -g bare-build`) — it is what produces the agent binary. If it is
missing the build now says so; it used to exit 144 with no output at all.

### On macOS

Everything above works, with three setup facts that are easy to get wrong and only one of which fails
loudly on its own.

```bash
podman machine set --memory 8192 --cpus 6   # resizes IN PLACE -- no need to destroy the machine
podman machine start
```

1. **Give the machine enough RAM.** The shipped limits want an 8 GiB memory cap plus a 4 GiB `/w`
   tmpfs, and tmpfs is charged to the memory cgroup. A 2 GiB machine cannot honour that, and nothing
   checks: you get an OOM-killed VM presenting as `podman exited <n>`.
2. **Keep the checkout under `/Users` or `/private`.** The seccomp profile is an absolute _host_ path
   read by the podman service _inside_ the VM. podman machine mounts those two via virtiofs, so a
   normal clone resolves. `/Volumes` is not mounted and fails with `opening seccomp profile failed`
   naming a path that plainly exists on your Mac — the launcher now explains that when it happens.
3. **`--tier machine` is required for every `run`.** `minTier` defaults to `microvm`, and krun is
   permanently unreachable on macOS: applehv guests get no `/dev/kvm`, and nested virtualisation needs
   M3+ and is not exposed by podman machine. So a default `run` correctly exits 78.

   `machine` (rank 70) is the honest name for what you get instead: containers run inside the podman
   machine VM, so an escape lands in the VM rather than on your Mac — a real boundary, but **one VM
   shared by every job**, where krun gives each job its own. The attestation records the tier and a
   `shared` flag, so a consumer can tell a shared VM from a dedicated remote builder.

`bare bin.js doctor` checks the three things above under `setup` and tells you which one is wrong.

The agent is cross-built for the podman **server**'s architecture, not this host's, so on Apple
Silicon you get an arm64 agent automatically. `bare bin.js doctor` reports all of it.

### Building the images

`scripts/build/agent.js` is required before any isolated tier can be tested. The agent is **baked
into the image** because there is no mount available to inject it — that is a consequence of the
no-host-mounts invariant, not an oversight.

It derives the target architecture from the **podman server** (`podman info --format {{.Host.Arch}}`),
not from this host, and refuses a mismatch before spending a minute on the build. That distinction is
not pedantry: on Apple Silicon `podman machine` runs an aarch64 Linux guest, so an x86-64 agent baked
into it is an `exec format error` reported as `podman exited 126` — which reads as a launcher bug.
`--cross` builds the binary for another machine and deliberately stops there, since `FROM
ubuntu:24.04` resolves to the _build_ host's arch and the resulting image would run on neither side.

It takes `--skip-binary` to reuse an existing binary, and **refuses** if that binary is older than
the agent sources, or if it is for a different architecture than the server. That guard exists because the failure mode is genuinely misleading: a stale agent
in a fresh image made every step die with `working directory does not exist: /w/src`, which looks
exactly like a bug in whatever you changed most recently.

> [!IMPORTANT]
> **The agent shares `lib/transfer.js` with the host.** If you change anything in `lib/` that the
> agent bundles, rebuild the agent _and_ every layered image, or the in-sandbox half of the change
> silently does not exist. This has already caused one real bug: after fixing the execute-bit
> handling in `transfer.js`, artifacts still came back non-executable because the baked agent was
> still writing `0644` on the way in. Rebuilding is `bare scripts/build/agent.js` plus the three
> `podman build` lines — the layered images must be rebuilt because they are `FROM` the base.
>
> **This includes pulling a branch, not just editing.** `out/` is gitignored, so a checkout that
> changes `lib/agent/` leaves you with a binary older than the source and nothing says so until a
> step behaves oddly. Hit for real moving the macOS branch back to Linux: the branch added an
> `fdScan` field to the hello response and the stale agent did not have it, so the handshake reported
> `unknown: agent predates the fdScan field`. That one surfaced cleanly because the field is
> explicitly version-checked — the general case does not. **Rebuild after any checkout that touches
> `lib/`.**

The images layer strictly:

```
etc/Containerfile             base: ubuntu:24.04 + the agent, nothing else
  └─ Containerfile.node       + node 22 (NodeSource, NOT ubuntu's 18.19.1 -- see below)
       ├─ Containerfile.bare-build   + bare-build and 13 prebuilt runtimes (~1.6 GB)
       └─ Containerfile.pear         + pear-build
```

Everything inherits the base, so the agent and the isolation posture are identical across
toolchains: a toolchain cannot weaken the sandbox, and there is one place to audit.

> [!WARNING]
> **Node 22 is a hard requirement, not a preference.** Ubuntu 24.04 packages node 18.19.1, and
> `bare-addon-resolve` calls `Array.prototype.with()` — ES2023, so node 20+ — on the branch guarded
> by `supportsUniversalPrebuilds(host)`, which is true for **darwin only**. On node 18 that is
> `TypeError: conditions.with is not a function` for `--host darwin-x64`, while every linux and
> win32 target builds cleanly. `Containerfile.node` asserts the capability at build time so the
> image fails to build rather than a workflow failing five targets in.

## Test layout

| Path                                | What it covers                                                                          |
| ----------------------------------- | --------------------------------------------------------------------------------------- |
| `test/schema.js`, `test/targets.js` | the workflow schema and target vocabulary, heavy on rejection cases                     |
| `test/argv.js`, `test/seccomp.js`   | pure functions; a full-argv snapshot and the exact seccomp errnos                       |
| `test/protocol.js`, `test/agent.js` | framing contract over an in-memory duplex pair; agent-side helpers                      |
| `test/transfer.js`, `test/store.js` | the tar validator and the drive-backed artifact store                                   |
| `test/lifecycle.js`                 | **one** Sandbox suite, run against every launcher — host subprocess, container, microVM |
| `test/argv-runs.js`                 | the generated argv is actually accepted by podman                                       |
| `test/cli.js`                       | the real CLI against `examples/`, asserting on the `--json` event stream                |
| `test/hello-pear.js`                | all three deployment stages end to end, asserting on `file(1)` per target               |
| `test/publish.js`                   | publish-job refusals, plus a real staged publish against a local DHT                    |
| `test/escape/`                      | escape suite **and its negative control**                                               |
| `test/fidelity.js`                  | byte-exactness and backpressure of the stdio transport (`bare test/fidelity.js`)        |

Container-dependent tests skip with a stated reason when podman or an image is missing, so the suite
stays green on a machine without a runtime — but it says so rather than quietly testing less.

Three things to know before trusting the suite:

- **The negative control is the most important test here.** `test/escape/index.js` runs the same
  probes against a deliberately weakened sandbox and requires them to fail. It has already caught a
  false pass: a probe used `ip route`, which is not installed in `ubuntu:24.04`, so _both_ postures
  reported zero routes and the hardened test passed for the wrong reason.
- **Escape assertions are tier-aware.** Under krun the workload legitimately runs as uid 0 with a
  full `CapEff`, because the VM is the boundary rather than the capability set. Asserting
  `CapEff == 0` there would be a wrong test, so host-safety probes run on both tiers and
  guest-privilege probes run only on `container`.
- **`test/argv.js` has a full-argv snapshot.** Any diff is a deliberate change to the isolation
  posture. If you change a limit or a flag, that test failing is the system working; read the diff
  before updating the golden.

`test/support/local-launcher.js` runs the agent as a plain host subprocess with no isolation. It
lives under `test/` on purpose: there is no code path from a workflow to it.

`test/support/dht.js` stands up a local DHT plus a seeding peer for the publish tests. The seeder is
not scaffolding — staging genuinely does not complete until another peer has the blocks, and there is
a separate test asserting that publishing with nobody seeding times out with a useful message.

## Module layout

```
bin.js                          paparam CLI
lib/schema/                     YAML -> normalize -> validate -> frozen Workflow. The ONLY place
                                that touches YAML, so replacing js-yaml is one swap.
lib/targets.js                  target vocabulary and the per-target capability rule
lib/toolchains.js               toolchain name -> image
lib/interpolate.js              the tiny {{ }} evaluator and the `if:` grammar
lib/graph.js                    ready-queue scheduler, cycle detection, --job filter
lib/isolation/detect.js         tier probing, refuse-to-run
lib/isolation/podman/argv.js    pure spec -> argv. THE security-critical file.
lib/isolation/podman/seccomp.js profile generator; output committed to etc/seccomp/
lib/isolation/podman/launcher.js
lib/sandbox.js                  driver-side handle: prepare / exec / dispose
lib/agent/                      in-sandbox agent, bare-build --standalone, baked into the image
lib/protocol.js                 hrpc schema + frame constructors
lib/transfer.js                 validating tar in/out. Never `podman cp`.
lib/store/                      artifacts, written against a DRIVE not a path
lib/prefetch.js                 lockfile-driven fetcher; executes no third-party code
lib/attestation.js              per-task and per-publish records
lib/run/                        job runner, step guards, output-file protocol
lib/config.js                   runner-side secrets. The only place a key exists.
lib/publish/                    the trusted side: drivers that may use a key
```

Conventions, per `bare-tui` / `bare-tcp` / `pear-build`: CJS, an `exports` map including
`"./package"`, explicit `files`, Apache-2.0 with LICENSE and NOTICE, `.prettierrc` =
`prettier-config-holepunch`, `brittle` / `lunte` / `prettier`, `test/index.js` aggregator, and an
`imports` map so modules load on both Node and Bare.

## Isolation

### The argv

T3 (`container`). T1 (`microvm`) adds the krun annotation and `--device /dev/kvm`:

```
podman run --rm --name bw-<id> --cidfile <state>/jobs/<id>/cid \
  --pull never --log-driver none -i \
  --userns auto:size=1024 --user 1000:1000 \
  --pid private --ipc private --uts private --cgroupns private \
  --cap-drop ALL --security-opt no-new-privileges \
  --security-opt seccomp=etc/seccomp/build-v1.json \
  --security-opt proc-opts=nosuid,nodev,noexec,hidepid=2 \
  --security-opt mask=/proc/scsi:/sys/firmware:/proc/kcore:/proc/keys \
  --read-only --read-only-tmpfs=false \
  --mount type=tmpfs,dst=/w,tmpfs-size=4g,tmpfs-mode=1777,nosuid,nodev \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g,mode=1777 \
  --tmpfs /run:rw,nosuid,nodev,noexec,size=16m --shm-size 64m \
  --network none --no-hosts \
  --memory 8g --memory-swap 8g --pids-limit 512 \
  --ulimit nofile=65536:65536 --ulimit nproc=512:512 --ulimit core=0:0 \
  --timeout 3600 --workdir /w/src \
  --env HOME=/w/home --env TMPDIR=/tmp --env CI=true \
  --entrypoint /opt/bw/agent <image>@sha256:<digest>
```

Non-obvious rationale, all of it learned the hard way:

- **`--userns auto:size=1024` is the single highest-value flag.** Host UID 1000 is unmapped, so
  container root owns nothing on the host.
- **`--read-only-tmpfs=false`** because podman's default would silently give a writable `/dev`,
  `/run`, `/tmp` and `/var/tmp`.
- **`/tmp` deliberately without `noexec`** — cmake/ninja/node-gyp exec from temp, and `noexec` is
  defeated by `memfd_create` anyway, so it buys nothing and breaks real builds.
- **`--log-driver none`** because journald is the default and an untrusted build must not write
  unbounded data into the host journal.
- **`--workdir /w/src` must be the tmpfs root's child, and `/w` needs `tmpfs-mode=1777`.** Both are
  required: podman creates the workdir as root _before_ dropping privileges. Either one missing
  shows `pwd` working and only writes failing, which is why it took two fixes.
- **`--dns=none` conflicts with `--network none`** and is not emitted.
- **`--cap-drop ALL`, not seccomp, is what blocks nested-userns escalation.** Measured both ways:

  ```
  podman defaults:   unshare -Ur  ->  uid=0, CapEff: 000001ffffffffff
  --cap-drop ALL:    unshare -Ur  ->  write failed /proc/self/uid_map: EPERM
  ```

  The seccomp profile is defense-in-depth on top of that, removing reachable kernel surface —
  several userns/mount LPEs need no capabilities at all.

The builder **rejects** these outright, snapshot-tested: `--privileged`, `--device` (except
`/dev/kvm` on T1), `--cap-add`, `--env-host`, `--userns=host|keep-id|nomap`, host `--pid`/`--ipc`/
`--uts`/`--network`, `-v`, `--mount type=bind`, `--volumes-from`, `seccomp=unconfined`,
`label=disable`, `unmask`, `--group-add keep-groups`, `-p`.

### Two invariants, enforced before any argv is emitted

- **No host bind mounts, ever.** Not a preference — rootless idmapped mounts are kernel-forbidden
  (`podman-run(1)`: "The Linux kernel does not allow the use of idmapped file systems for
  unprivileged users"), so a bind mount under `--userns=auto` lands as `nobody` and is unwritable.
  All data crosses as a validated stream instead, which also deletes the host-path-rebasing problem
  that bind mounts create.
- **No host environment inheritance.** `bare-subprocess` defaults `env` to the parent's environment,
  so the alternative is one omission away from handing `GH_TOKEN` to a build.

### The resource limits are not independent

`resolveLimits()` in `argv.js` refuses a spec where the tmpfs sizes plus process headroom exceed the
memory limit, and this is not pedantry. **A tmpfs is RAM-backed, so every byte written to `/w`,
`/tmp` or `/dev/shm` is charged to the memory cgroup.** Measured: writing 1500 MiB into a 4 GiB tmpfs
under `--memory 1g` is **OOM-killed at ~1020 MiB**, not given ENOSPC.

The old defaults promised an 8 GiB workspace under a 4 GiB memory cap — a workspace twice the size of
the one you could actually fill, and it turned "the disk filled up" into "SIGKILL". The footgun the
check really catches is overriding _one_ tmpfs size and inheriting the others.

### `nofile` is 65536, and 4096 was not enough

Worth recording because nothing pointed at file descriptors. `bare-pack` traverses a dependency graph
with **unbounded concurrency** (its `concurrency` option defaults to 0, i.e. no semaphore) and its
`readModule` swallows every errno:

```js
exports.readModule = async function readModule(url) {
  try {
    return await exports.readFile(url)
  } catch {
    return null
  }
}
```

A null read is indistinguishable from a missing file, so EMFILE surfaces as
`MODULE_NOT_FOUND: Cannot find module 'b4a'` for a module sitting right there on disk. Measured on
`hello-pear-bare` (140 packages) at 4096 fds: **330–593 EMFILE errors per build, a different module
named each run, roughly a 2-in-3 failure rate**. The dependency graph is the input, so a toy project
builds fine and a real one does not — the worst possible shape for a default. Two upstream fixes are
worth sending: don't swallow the errno, and default to a bounded concurrency.

### Getting data in and out

No host mounts means everything crosses as a **validated tar stream**, and `lib/transfer.js` decides
entry by entry what is allowed to exist: regular files and directories only (no symlinks, hardlinks,
fifos or devices) · no absolute paths · no `..` in any component · no control characters in names ·
depth, length, entry-count and byte caps · case-insensitive collision detection ·
Windows-reserved-name rejection · extraction only into a fresh empty directory.

Symlinks are _skipped_ on the way out rather than followed, so a build cannot plant one to smuggle
out anything the sandbox merely had access to.

**Exactly one mode bit survives: owner-execute.** setuid, setgid and sticky are discarded by
construction rather than by masking. Both halves matter — a setuid bit in an artifact must never
reach the host, but a distributable that comes back non-executable is not a distributable. That bit
is also part of the artifact digest, because two trees differing only in what is runnable are
different artifacts and one of them is broken.

### The agent

Steps run through a long-lived agent inside the sandbox, speaking
[hrpc](https://github.com/holepunchto/hrpc) over fd 0/1. Not `podman exec`: a krun microVM cannot be
re-entered at all. That constraint turned out to be a gift — the same duplex works for a container, a
microVM, and later a remote peer over hyperdht, so remote dispatch becomes a transport swap rather
than a rewrite.

```js
const { create: sandbox } = require('bare-workflow/sandbox')
const { create: launcher } = require('bare-workflow/isolation/podman/launcher')

const box = sandbox({ launcher: launcher(spec) })
await box.prepare() // pay container setup ONCE per job

const run = box.exec({ run: 'npm ci && npm test' }, { timeoutMs: 600000 })
run.stdout.on('data', (chunk) => Bare.stdout.write(chunk))
const { code, timedOut, truncated } = await run.wait()

await box.dispose()
```

**Step commands are data, never host argv.** `exec({ run: '...', shell: 'bash' })` sends a frame and
the agent picks the shell _inside_ the sandbox, so no host-side quoting bug can become host command
injection.

Cancellation is a four-level ladder — agent SIGTERM→SIGKILL on the process group, `podman kill`,
podman `--timeout` / `RuntimeMaxSec`, then `systemctl --user kill` / `cgroup.kill` — because a
hostile build will ignore the polite ones. On startup the launcher reaps orphaned `bw-*` containers,
scopes and volumes.

## Sharp edges

Things that have cost real debugging time here.

- **`{{` starts a YAML flow mapping.** `steps: [echo '{{ x }}']` is a syntax error. A malformed _test
  fixture_ once looked exactly like a broken feature.
- **`require(someVariable)` is invisible to bare-build's bundler.** An "optional" dependency simply is
  not in the binary. `picomatch` was silently absent, so a globbed artifact `get` matched nothing and
  produced empty artifacts that looked like a broken build.
- **`require.main === module` does not hold in a bare-build standalone bundle** — hence
  `lib/agent/bin.js` as a separate entry.
- **Stripping the agent binary segfaults it.** 84 MB works; a 64 MB stripped build core-dumps.
- **hrpc's append-only guarantee protects the _encoding_, not the _call_.** An older agent crashes
  with `this._handlers[command] is not a function` on an unknown command, hence capability
  advertisement in the hello response and an `AGENT_TOO_OLD` error.
- **hrpc handler shapes are asymmetric.** A streaming-request command must **return** its reply; a
  streaming-response command receives the request as `stream.data`, with no `'data'` event.
- **systemd rejects podman's `b` byte suffix.** `MemoryMax=4294967296b` fails with "Invalid
  argument", hence two separate formatters so neither side can borrow the other's spelling.
- **`systemd-run --user` needs `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR`**, which is why
  `requiredHostEnv()` is an allowlist that still refuses `GH_TOKEN`, npm and AWS variables.
- **`Duplex.from({readable, writable})` is object-mode**, so the stdio bridge is written explicitly
  in bytes. `bare-stream` follows Node stream conventions, not streamx.
- **"any fd > 2" is a useless leak check** — Bare holds ~13 of its own. Classify instead.
- **`spawn()` reports a missing cwd and a missing executable with the same ENOENT**, so the agent
  stats the cwd first to tell them apart.
- **`npm ci` in the sandbox emits `TAR_ENTRY_ERROR EPERM: fchown` warnings.** Expected and benign:
  `--cap-drop ALL` means npm cannot chown extracted files. The install completes correctly.
- **Prettier reformatting silently broke two patches** during development; both bugs were caught by
  tests that assert on records rather than on log output. Prefer assertions on structured data.

## Contributing

- `npm run lint` must pass (`prettier --check` and `lunte`).
- New behaviour needs a test that would fail without it. For anything touching isolation, that means
  a test in `test/escape/` that also fails against the weakened provider.
- Errors should name the path, the line and a suggestion. Error quality is a feature here, not
  politeness — GHA's habit of accepting a typo and silently doing nothing is the thing being
  rejected.
- Comments should say _why_, especially where the reason is a measurement. Most of the non-obvious
  code here exists because something was tried and failed.
