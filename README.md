# bare-workflow

A P2P build farm for Holepunch, running sandboxed workflows on [Bare](https://github.com/holepunchto/bare).

> [!NOTE]
> This is an experimental library, and early. A version 1.0.0 release will signal stability.
> Today it runs a dependency graph of jobs across targets in microVMs, moves artifacts between them,
> and installs npm dependencies with **no network at all**. Free-form matrix axes, signing, and the
> P2P farm are not built yet.

```console
$ bare-workflow run examples/hello.yml
◉ hello  tier=microvm  1 task
  ◉ main:host :: echo "hello from inside the sandbox"
    hello from inside the sandbox
  ✔ main:host :: echo "hello from inside the sandbox"  36ms
  ◉ main:host :: uname -r
    6.12.91
  ✔ main:host :: uname -r  31ms
  ✔ main:host: success
```

That `6.12.91` is the guest kernel, not the host's — the step really ran inside the VM.

## Why

`pear build` does not compile anything — it assembles already-built per-platform bundles into
`<target>/by-arch/<plat-arch>/app/<Name>`. Producing those inputs means running `bare-make` /
`npm run make` on a machine of that OS, with that OS's signing chain. Emulation cannot fix that,
so a farm of heterogeneous _real_ peers is the answer, and every job has to be safe to run on
someone else's machine.

That last part is the hard part, and it is where most of the work has gone: the isolation layer came
first, and the workflow engine is being built on top of it rather than the other way round.

## The workflow

Not GitHub Actions. No `uses:`, no remote action fetching, no expression language. A six-line
workflow stays six lines:

```yaml
version: 1
targets: [linux-x64]
steps:
  - npm ci
  - npm test
```

Top-level `steps:` is sugar for a single job named `main`; the full form uses `jobs:`. `version:` is
required and pinned, so semantics can change later without heuristics.

`targets:` is one axis serving two purposes — a build matrix today, and a **placement constraint**
for the farm tomorrow. `target: darwin-arm64` already means "needs a machine that can build
darwin-arm64", so capability matching falls out of the schema instead of being bolted on later. The
vocabulary is closed and identical to `pear build`'s flags, so a typo is a parse error rather than a
job that silently never runs:

```
$ bare-workflow validate broken.yml
✖ SCHEMA_INVALID: targets[0]: unknown target "darwin-arm46"; did you mean "darwin-arm64"? (line 2)
```

Error quality is a feature here, not politeness. Unknown keys, unresolvable `needs`, malformed
durations and duplicate step ids are all rejected with a path, a line, and a suggestion.

### Interpolation

`{{ }}` over a closed set of roots — `target`, `matrix`, `env`, `needs`, `steps`, `job`, `run` — with
no functions and no arithmetic. **An unknown reference is a hard error, never an empty string**:

```
✖ EXPR_UNKNOWN_REFERENCE: unknown reference "needs.version.outputs.nope"; available: value
```

That single decision removes most of the mystery from a failing workflow. GHA substitutes `''` and
lets the build carry on doing the wrong thing indefinitely.

`if:` takes a small predicate grammar — `success()` / `failure()` / `always()` / `cancelled()`, `==`,
`!=`, `in [...]`, `and` / `or` / `not`, parentheses — with paths written bare:

```yaml
- run: ./upload
  if: success() and target.platform != 'win32'
```

> [!TIP]
> `{{` starts a YAML flow mapping, so an interpolation inside a **flow** sequence is a syntax error:
> `steps: [echo '{{ x }}']` will not parse. Use block style, which is what you want for anything
> non-trivial anyway.

### Jobs, targets and data flow

`needs` orders jobs; a job with several targets becomes several tasks, and a dependency waits for all
of them. Outputs are declared, written to a **file** (`$BW_OUTPUT`), and parsed on the trusted side:

```yaml
jobs:
  version:
    outputs:
      value: '{{ steps.read.outputs.version }}'
    steps:
      - id: read
        run: echo "version=1.2.3" >> $BW_OUTPUT

  package:
    needs: version
    steps:
      - run: echo "packaging {{ needs.version.outputs.value }}"
```

A file rather than GHA's `::set-output::` stdout scraping, because in a farm log lines are
attacker-controlled by construction — a build could otherwise forge any output it liked. A file
descriptor is a capability; stdout is a broadcast.

Reading `needs.<job>.outputs.*` from a job that ran for **several** targets is refused rather than
guessed at, because there is genuinely more than one value:

```
✖ needs.multi.outputs.value is ambiguous: multi ran for 2 targets (linux-arm64, linux-x64).
  Give multi a single target, or read it per target.
```

### Toolchains

`toolchain:` selects the sandbox image, and it is what replaces GHA's `uses:` entirely — a curated,
versioned set rather than fetching third-party code into the runner. Every toolchain image layers on
the **same base**, so the agent and the isolation posture are identical across all of them: a
toolchain cannot weaken the sandbox, and there is one place to audit.

```yaml
version: 1
toolchain: node # or per job
steps:
  - npm ci --offline --ignore-scripts --cache /w/cache
```

The default is `bare`: the base image carries the agent and nothing else, so a workflow that needs
npm has to say so rather than every sandbox shipping tooling it does not use. A typo is caught at
parse time, and a toolchain whose image has not been built is refused **before anything runs**:

```console
$ bare-workflow run examples/offline.yml
✖ required sandbox image not built:
  toolchain node: localhost/bare-workflow-node:dev
    build it: podman build -f etc/Containerfile.node -t localhost/bare-workflow-node:dev .
```

`bare-workflow doctor` lists every toolchain and whether it is built. `--image` overrides the lot,
for trying an image that has no registry entry yet.

## Isolation

Tiers, ranked by what a full compromise of the workload actually buys an attacker:

| Tier                | Mechanism                                                                                 | Boundary                |
| ------------------- | ----------------------------------------------------------------------------------------- | ----------------------- |
| `microvm` (default) | `podman --annotation run.oci.handler=krun`, nested inside the hardened container flag set | a separate guest kernel |
| `container`         | hardened rootless podman + crun                                                           | the host kernel         |

There is deliberately no host-execution tier. A command allowlist over host processes is defeated
by the first `sh -c`, and it is not offered even as a fallback.

Enable the microVM tier with:

```
sudo pacman -S libkrun libkrunfw    # crun is already built +LIBKRUN
```

`crun` selects the microVM path by **annotation**, not `--runtime krun`.

### What the flags actually buy

Two invariants are enforced in `lib/isolation/podman/argv.js` before any argv is emitted:

- **No host bind mounts, ever.** Not a preference — rootless idmapped mounts are kernel-forbidden
  (`podman-run(1)`: "The Linux kernel does not allow the use of idmapped file systems for
  unprivileged users"), so a bind mount under `--userns=auto` lands as `nobody` and is unwritable.
  All data crosses as a validated stream instead, which also deletes the host-path-rebasing problem.
- **No host environment inheritance.** `bare-subprocess` defaults `env` to the parent's
  environment, so the alternative is one omission away from handing `GH_TOKEN` to a build.

`--cap-drop=ALL` is the flag doing the heavy lifting on the container tier — measured, it is what
blocks nested-userns escalation, not the seccomp profile:

```
podman defaults:   unshare -Ur  ->  uid=0, CapEff: 000001ffffffffff
--cap-drop ALL:    unshare -Ur  ->  write failed /proc/self/uid_map: EPERM
```

The generated seccomp profile (`etc/seccomp/build-v1.json`) is defense-in-depth on top of that,
removing reachable kernel surface — several userns/mount LPEs need no capabilities at all.

## The agent

Steps run through a long-lived agent inside the sandbox, speaking [hrpc](https://github.com/holepunchto/hrpc)
over fd 0/1. Not `podman exec`: a krun microVM cannot be re-entered at all. That constraint turned
out to be a gift — the same duplex works for a container, a microVM, and later a remote peer over
hyperdht, so remote dispatch becomes a transport swap rather than a rewrite.

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

`prepare` / `exec` / `dispose` is the shape, so a ten-step job pays setup once instead of ten
times. Output streams as it happens with byte caps, rather than being collected after exit.

### Getting data in and out

There are no host mounts — rootless idmapped bind mounts are kernel-forbidden, and refusing them
outright removes the whole bind-mount attack surface along with the host-path-rebasing problem that
comes with it. So everything crosses as a **validated tar stream**, and `lib/transfer.js` decides
entry by entry what is allowed to exist:

regular files and directories only (no symlinks, hardlinks, fifos or devices) · no absolute paths ·
no `..` in any component · no control characters in names · depth, length, entry-count and byte caps ·
modes masked so a setuid bit cannot survive · case-insensitive collision detection · Windows-reserved
names rejected · extraction only into a fresh empty directory.

Symlinks are _skipped_ on the way out rather than followed, so a build cannot plant one to smuggle
out anything the sandbox merely had access to.

Artifacts are declared on both sides, and the name is interpolated so a fan-out job produces one
artifact per target instead of several tasks fighting over a single name:

```yaml
jobs:
  build:
    targets: [linux-x64, linux-arm64]
    artifacts:
      out:
        - name: app-{{ target }}
          path: out/**
          if-no-files-found: error

  assemble:
    needs: build
    artifacts:
      in:
        - name: app-linux-x64
          to: ./stage/linux-x64
```

The store is written against a **drive**, not a path. `localdrive` and `hyperdrive` share a surface,
so v1 passes a Localdrive and the farm later passes a Hyperdrive — at which point returning an
artifact from a peer is `drive.mirror()`, and `pear stage` / `seed` / `dump` already speak the format.

### Dependencies with no network

`network: none` is only honest if a real build can still install its dependencies. The runner
prefetches on the **host**, before any sandbox exists:

```yaml
version: 1
source: ./project

jobs:
  test:
    prefetch: [npm]
    steps:
      - run: npm ci --offline --ignore-scripts --cache /w/cache
      - run: npm test
```

```console
$ bare-workflow run examples/offline.yml --image localhost/bare-workflow-node:dev
◉ prefetching 1 package from the lockfile
  ✔ 1 fetched, 0 already cached
  ↓ test:host :: source  2 files
  ↓ test:host :: cache  1 files
  ✔ test:host :: install from the prefetched cache, offline  2.2s
    confirmed: no default route, no egress
  ✔ test:host :: run the project's tests  2.3s
```

Three properties, and the first two are the whole point:

- **It resolves nothing.** Every URL and hash comes from the committed lockfile. No registry
  metadata request, no version resolution, no dependency solving — if it is not in
  `package-lock.json` it is not fetched.
- **It executes no package code.** Nothing is unpacked and no lifecycle script runs; tarballs are
  downloaded and verified, full stop. That is also why the install uses `--ignore-scripts`, which is
  already the house style in `actions/node-base`.
- **Every tarball is verified** against the lockfile's `integrity` before it is kept. A registry
  serving different bytes than the repository recorded is a supply-chain event, not a retry.

A lockfile pointing at an unexpected host, or missing an integrity hash, is refused before anything
is fetched.

## CLI

```
bare-workflow validate <file>       # parse and report; exit 1 on a bad workflow
bare-workflow run <file>            # run it in the strongest available sandbox
bare-workflow doctor                # what tiers and targets this host supports
bare-workflow artifacts <run-id>    # list, or --get <name> to extract
```

`run` takes `--job <name>`, `--tier <microvm|container>`, `--image <ref>`, `--env KEY=VALUE`
(repeatable), and `--json` for a newline-delimited event stream using the same `{cmd, tag, data}`
envelope as `pear --json`.

Exit codes are meaningful: `0` success, `1` a step or workflow failed, `2` usage error, and **`78`
(EX_CONFIG) when no adequate isolation tier is available** — the host is not configured to run this
safely, which is deliberately not the same thing as the build failing.

## Development

```bash
npm install

npm run build:rpc          # regenerate schema/spec from schema/builder (committed output)
bare scripts/build/agent.js  # build the agent binary + the sandbox base image
podman build -f etc/Containerfile.node -t localhost/bare-workflow-node:dev .  # a node toolchain on top

npm test
npm run lint
```

`scripts/build/agent.js` is required before the isolated tiers can be tested — the agent is baked
into the image because there is no mount available to inject it. Without it, `test/lifecycle.js`
still runs, but says which tiers it skipped and why.

It takes `--skip-binary` to reuse an existing binary, and **refuses** if that binary is older than
the agent sources. That guard exists because the failure mode is genuinely misleading: a stale agent
in a fresh image made every step die with `working directory does not exist: /w/src`, which looks
exactly like a bug in whatever you changed most recently.

### Test layout

| Path                                | What it covers                                                                          |
| ----------------------------------- | --------------------------------------------------------------------------------------- |
| `test/schema.js`, `test/targets.js` | the workflow schema and target vocabulary, heavy on rejection cases                     |
| `test/cli.js`                       | the real CLI against `examples/`, asserting on the `--json` event stream                |
| `test/argv.js`, `test/seccomp.js`   | pure functions; a full-argv snapshot and the exact seccomp errnos                       |
| `test/protocol.js`                  | framing contract over an in-memory duplex pair                                          |
| `test/lifecycle.js`                 | **one** Sandbox suite, run against every launcher — host subprocess, container, microVM |
| `test/argv-runs.js`                 | the generated argv is actually accepted by podman                                       |
| `test/escape/`                      | escape suite **and its negative control**                                               |
| `test/fidelity.js`                  | byte-exactness and backpressure of the stdio transport (`bare test/fidelity.js`)        |

Two things worth knowing before trusting the suite:

- **The negative control is the most important test here.** `test/escape/index.js` runs the same
  probes against a deliberately weakened sandbox and requires them to fail. It has already caught
  a false pass in this repo: a probe used `ip route`, which is not installed in `ubuntu:24.04`, so
  both postures reported zero routes and the hardened test passed for the wrong reason.
- **Escape assertions are tier-aware.** Under krun the workload legitimately runs as uid 0 with a
  full `CapEff`, because the VM is the boundary rather than the capability set. Asserting
  `CapEff == 0` there would be a wrong test, so host-safety probes run on both tiers and
  guest-privilege probes run only on `container`.

`test/support/local-launcher.js` runs the agent as a plain host subprocess with no isolation. It
lives under `test/` on purpose: there is no code path from a workflow to it.

## License

Apache-2.0
