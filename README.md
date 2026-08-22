# bare-workflow

Build your Pear app for every platform, from one machine, in a sandbox — on [Bare](https://github.com/holepunchto/bare).

> [!NOTE]
> Experimental and early; 1.0.0 will signal stability. Linux and macOS hosts; `darwin-arm64` still
> needs a Mac-native tier — see [Platform support](#platform-support).

Point it at a [hello-pear-bare](https://github.com/holepunchto/hello-pear-bare) project and it
cross-builds **five of the six desktop distributables from a single Linux machine**, assembles the
Pear `by-arch/` deployment folder, and stages it — each step in a microVM with no network access.

```console
$ bare-workflow run .github/build.yml --concurrency 3
◉ hello-pear-bare  tier=microvm  toolchain=bare-build  6 tasks
  ✔ make:linux-x64      7.0s
  ✔ make:linux-arm64    7.4s
  ✔ make:win32-x64      3.4s
  ✔ make:win32-arm64    3.0s
  ✔ make:darwin-x64     5.5s
  ⊘ make:darwin-arm64: not buildable here
```

Those are real binaries — `ELF … aarch64`, `PE32+ … ARM64`, `Mach-O … x86_64` — built without a
compiler, a Windows machine, or a Mac. `darwin-arm64` is the one exception, and it is _reported_
rather than silently produced; [see below](#why-darwin-arm64-needs-a-mac).

## Requirements

- **Linux** (x64 or arm64), or **macOS** (Apple Silicon or Intel)
- [**Bare**](https://github.com/holepunchto/bare) — `npm i -g bare-runtime`
- **podman**, rootless is fine — `sudo pacman -S podman` / `sudo apt install podman` /
  `brew install podman`
- **libkrun**, for the microVM tier — `sudo pacman -S libkrun libkrunfw`. **Linux only**: krun needs
  `/dev/kvm`, which a macOS podman machine does not provide. On macOS the strongest tier available is
  `machine`, so runs need an explicit `--tier machine`.

On macOS, `podman machine` must be started and given enough memory for the default limits
(`podman machine set --memory 8192`), and the checkout has to live somewhere the machine mounts —
`/Users` or `/private`, not `/Volumes`. See [DEVELOPMENT.md](DEVELOPMENT.md) for the details.

Check your machine before anything else:

```console
$ bare-workflow doctor
podman     6.1.0
tiers
  microvm    rank 90   ✔ available
  machine    rank 70   ✖ containers run directly on this host, so there is no machine boundary
  container  rank 50   ✔ available
platform   linux-x64  (24 cpus)
targets    host, linux-x64, linux-arm64, darwin-x64, win32-x64, win32-arm64
toolchains
  bare        ✔ built     localhost/bare-workflow-base:dev
  node        ✔ built     localhost/bare-workflow-node:dev
  bare-build  ✔ built     localhost/bare-workflow-bare-build:dev
  pear        ✔ built     localhost/bare-workflow-pear:dev
```

If a toolchain says `not built`, build it — see [DEVELOPMENT.md](DEVELOPMENT.md#building-the-images).
If no tier is available the runner **refuses to run** rather than falling back to something weaker,
and tells you what to install.

## Your first workflow

Start from the template:

```bash
git clone https://github.com/holepunchto/hello-pear-bare my-app
cd my-app
```

Add `build.yml` to it:

```yaml
version: 1
name: my-app
source: . # the directory to copy into the sandbox
toolchain: bare-build # the image that has bare-build and the prebuilt runtimes

jobs:
  make:
    targets: [linux-x64, linux-arm64, win32-x64, win32-arm64, darwin-x64, darwin-arm64]
    prefetch: [npm] # download deps on the host, from the lockfile, before the sandbox exists
    artifacts:
      out:
        - name: dist-{{ target }}
          path: out/{{ target }}/**
          if-no-files-found: error
    steps:
      - name: install, offline
        run: npm ci --omit=dev --offline --ignore-scripts --cache /w/cache

      - name: make {{ target }}
        run: npm run make:{{ target }}
        timeout: 15m
```

Then run it:

```bash
bare-workflow run build.yml --concurrency 3
```

Three things in there are worth understanding, because they are the difference between this working
and this looking like it worked.

**Call `make:<target>`, never `make`.** The template's `npm run make` reads `os.platform()` and
builds _one_ target — it is a local convenience, not a matrix. Using it would build a single binary
and look like it had done all six.

**`prefetch: [npm]` is what makes `network: none` possible.** The runner reads the `resolved` URLs
and `integrity` hashes already committed in your `package-lock.json`, downloads and verifies those
exact tarballs on the host, and mounts them read-only into the sandbox. It resolves nothing and runs
no package code. Inside, `npm ci --offline` installs from that cache with no network at all.

**`{{ target }}` fans the job out.** One job definition becomes one task per target, and the
artifact name is interpolated so they do not fight over one name.

### Getting your artifacts out

```console
$ bare-workflow artifacts <run-id>
  dist-darwin-x64            1 file   79.0 MiB
  dist-linux-arm64           1 file   94.6 MiB
  dist-linux-x64             1 file   94.0 MiB
  dist-win32-arm64           1 file   50.7 MiB
  dist-win32-x64             1 file   54.2 MiB
                                  5  372.6 MiB  total

$ bare-workflow artifacts <run-id> --get dist-linux-x64 --to ./dist
✔ dist-linux-x64 -> ./dist  (1 files, 98567680 bytes)
```

The extracted binary is executable and runs. On a Linux x64 host you can check immediately:

```console
$ ./dist/hello-pear-bare --version
hello-pear-bare v0.0.0-rc.0
```

## The three deployment stages

The [Pear deployment docs](https://docs.pears.com/how-to/operate-an-app/manual-deployment/deployment/)
describe three stages. All three are one workflow file — see
[`examples/hello-pear.yml`](examples/hello-pear.yml) for the complete version.

| Stage                   | Job        | Runs                                           |
| ----------------------- | ---------- | ---------------------------------------------- |
| 1. Make distributables  | `make`     | sandboxed, one task per target, no network     |
| 2. Build deployment dir | `assemble` | sandboxed, `pear-build` over stage 1's output  |
| 3. Stage                | `stage`    | **trusted** — holds the key, needs the network |

### Stage 2 — the deployment folder

`pear build` does not compile. It mirrors already-built per-target binaries into
`<target>/by-arch/<plat-arch>/app/`, which is where the OTA updater and `pear-install` look. So it is
one host-only job consuming stage 1's artifacts:

```yaml
assemble:
  needs: make
  targets: [host]
  toolchain: pear # a different image: bare-build has the runtimes, pear has the packager
  artifacts:
    in:
      - name: dist-linux-x64
        to: ./stage/linux-x64
      # ... one per target
    out:
      - name: deployment
        path: build/**
  steps:
    - run: |
        pear-build --package ./package.json \
          --linux-x64-app   ./stage/linux-x64/hello-pear-bare \
          --linux-arm64-app ./stage/linux-arm64/hello-pear-bare \
          --win32-x64-app   ./stage/win32-x64/hello-pear-bare.exe \
          --target ./build/hello-pear-bare-1.0.0
```

> [!IMPORTANT]
> **The filename must equal your `package.json` `name`.** `pear-runtime-updater` fetches
> `/by-arch/<host>/app/<name>` and `pear-install` derives the installed binary name the same way,
> while `bare-build` puts `--name` through a normalizer that lowercases and collapses
> non-alphanumerics. So `"name": "MyApp"` builds `my-app` while the updater hunts for `MyApp` —
> `update not found`, long after CI went green. Keep `name` lowercase-and-hyphens and it cannot bite.

### Stage 3 — staging

This is the one job that does **not** run in a sandbox, because it cannot: staging needs a Hyperswarm
connection and your app's primary key, which are the two things a sandbox exists to withhold. So it
is a `publish:` job with a deliberately tiny surface — no `steps:`, nothing to run, nowhere for a
compromised build to sit next to the key:

```yaml
stage:
  needs: assemble
  publish:
    driver: pear-ci
    artifact: deployment # a digest-bound tree a sandboxed job produced
    name: my-app # drive namespace
    key: my-app # a NAME in your runner config -- never the key itself
    dry-run: false
```

Put the key in `~/.config/bare-workflow/config.json`, mode `0600`:

```json
{ "keys": { "my-app": { "primaryKey": "<64 hex chars>" } } }
```

Nothing is published without **both** `dry-run: false` in the file and `--publish` on the command
line. Either alone is a dry run — which still reports the link, so you can preview safely:

```console
$ bare-workflow run build.yml --publish
  ◉ stage:host :: publishing deployment -> my-app
    change /by-arch/linux-x64/app/hello-pear-bare
  ✔ stage:host: published pear://qdw6pk5qknsa73fzjq3pk6oppeb1ri31qfrsadx4drur7kcm1e3y
    1 entry changed, snapshot length 4 -> 7
```

> [!WARNING]
> **Staging is not finished until another peer has replicated the blocks.** If nothing is seeding your
> drive, the publish times out and says so. `pear seed` has to be running somewhere permanent — it is
> infrastructure, not a build step.

Two more things about publishing:

- **The snapshot is durable state**, kept at `<state>/pear/<name>/snapshot.json`. Lose it and the
  next publish re-uploads everything; copy it to a second machine and the two will diverge on one
  drive. Keep it.
- **Promotion is not automated, on purpose.** `pear stage` is documented as being for previews and
  staging, _not_ production, and multisig exists precisely so one machine cannot redefine a release
  line. There is no `provision`, `multisig` or `seed` driver and there will not be one.

## Why darwin-arm64 needs a Mac

`bare-build` never compiles. It injects your JS bundle into a _prebuilt_ Bare runtime with
`bare-lief` — an ELF segment, a PE section, a Mach-O segment — and those runtimes are ordinary npm
packages with no `os`/`cpu` fields, so every host has all of them. That is why cross-building works
at all, and why it needs no toolchain.

The exception is signing. The `darwin-arm64` runtime ships **ad-hoc signed**; injecting into it
invalidates that signature; and Apple Silicon refuses to execute an arm64 Mach-O without a valid one.
`bare-build` only re-signs when the build host is a Mac. So a Linux-built `darwin-arm64` binary is
dead on arrival, and the runner reports it instead of producing it.

Capability here is therefore **per target, not per platform**: a target is buildable unless it needs a
signature this host cannot issue. `darwin-x64` builds fine from Linux (its runtime carries no
signature to invalidate); `win32-*` build fine (Windows runs unsigned binaries — SmartScreen
friction, not failure).

Everything cross-built is **unsigned**. Fine on Linux; SmartScreen friction on Windows; Gatekeeper
quarantine on macOS. Real signing is not implemented yet.

## Writing workflows

Not GitHub Actions: no `uses:`, no remote action fetching, no expression language. A six-line
workflow stays six lines.

```yaml
version: 1
targets: [linux-x64]
steps:
  - npm ci
  - npm test
```

Top-level `steps:` is sugar for a single job named `main`. `version:` is required and pinned.

**Errors name the problem.** Unknown keys, unresolvable `needs`, bad durations, duplicate step ids and
unknown targets are all rejected with a path, a line and a suggestion — before anything runs:

```console
$ bare-workflow validate broken.yml
✖ SCHEMA_INVALID: targets[0]: unknown target "darwin-arm46"; did you mean "darwin-arm64"? (line 2)
```

### Interpolation

`{{ }}` over a closed set of roots — `target`, `matrix`, `env`, `needs`, `steps`, `job`, `run` — with
no functions and no arithmetic. **An unknown reference is a hard error, never an empty string:**

```console
✖ EXPR_UNKNOWN_REFERENCE: unknown reference "needs.version.outputs.nope"; available: value
```

`{{ target }}`, `{{ target.platform }}` and `{{ target.arch }}` are the ones you will use.

> [!TIP]
> `{{` starts a YAML flow mapping, so an interpolation inside a **flow** sequence will not parse:
> `steps: [echo '{{ x }}']`. Use block style.

### Conditions

`if:` takes a small predicate grammar — `success()` / `failure()` / `always()` / `cancelled()`, `==`,
`!=`, `in [...]`, `and` / `or` / `not`, parentheses — with paths written bare:

```yaml
- run: ./upload
  if: success() and target.platform != 'win32'
```

### Passing values between jobs

`needs` orders jobs. Outputs are declared and written to a **file**, never scraped from stdout:

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

### Toolchains

`toolchain:` picks the sandbox image, per workflow or per job. There is no `uses:` and no remote
code fetching.

| Toolchain    | Contains                                                     |
| ------------ | ------------------------------------------------------------ |
| `bare`       | the default: bash and the agent, nothing else                |
| `node`       | node 22 and npm                                              |
| `bare-build` | node, npm, `bare-build` with all prebuilt runtimes (~1.6 GB) |
| `pear`       | node, npm, `pear-build` for assembling `by-arch/` folders    |

A typo is caught at parse time, and an image that has not been built is refused **before anything
runs**, with the command that builds it.

### Assurances you get for free

Every task writes an attestation, so what ran and under what isolation is a checkable fact rather
than a claim:

```console
$ bare-workflow attest <run-id>
run        mt3fxjut  success
workflow   hello-pear-bare
tier       microvm  (minimum required: microvm)
source     e391b8a8330e
image      localhost/bare-workflow-bare-build:dev@sha256:89395ac6b38a...
tasks
  ✔ make:linux-x64           microvm
                             seccomp ab8863e0a4b21cc4...
    ↑ dist-linux-x64         1 files  sha256:154c0e61980e...
```

It records the tier, the image digest, the sha256 of the seccomp profile that was actually applied,
the full argv, and a digest over every artifact tree. Records are written for failed tasks too. A
workflow can _demand_ isolation with `tier: microvm`, and the runner will refuse to run rather than
quietly give you less.

## CLI

```
bare-workflow validate <file>       # parse and report; exit 1 on a bad workflow
bare-workflow run <file>            # run it in the strongest available sandbox
bare-workflow run <file> --publish  # ... and let publish jobs actually publish
bare-workflow doctor                # tiers, targets and toolchains on this host
bare-workflow artifacts <run-id>    # list, or --get <name> --to <dir> to extract
bare-workflow attest <run-id>       # what ran, under what isolation, producing what bytes
```

`run` also takes:

| Flag                |                                                                             |
| ------------------- | --------------------------------------------------------------------------- |
| `--job <name>`      | run one job and its dependencies                                            |
| `--concurrency <n>` | how many tasks at once (default 1)                                          |
| `--tier <name>`     | `microvm` (default), `machine`, or `container`                              |
| `--state <dir>`     | where artifacts and run records go (default `.bw-state`)                    |
| `--env KEY=VALUE`   | extra environment for every step, repeatable                                |
| `--config <file>`   | runner config holding named keys                                            |
| `--json`            | newline-delimited `{cmd, tag, data}` events, same envelope as `pear --json` |

Exit codes: `0` success, `1` a step or workflow failed, `2` usage error, **`78` the host is not
configured to run this** — no adequate isolation tier, an unbuilt toolchain image, or a publish key
that does not resolve. That last one is deliberately distinct from a build failure.

## Isolation, briefly

| Tier                | Rank | Mechanism                                                              | Boundary                         |
| ------------------- | ---- | ---------------------------------------------------------------------- | -------------------------------- |
| `microvm` (default) | 90   | `podman --annotation run.oci.handler=krun`, nested in the hardened set | a separate guest kernel, per job |
| `machine`           | 70   | the same hardened container, but podman is a **remote** client         | a separate machine, **shared**   |
| `container`         | 50   | hardened rootless podman + crun                                        | the host kernel                  |

`machine` is what you get on macOS and Windows, where podman talks to a service inside a
`podman machine` VM: an escape lands in the VM rather than on your laptop, which is a real boundary —
but it is one VM shared by every job, where `microvm` gives each job its own. That difference is
recorded in the attestation (`isolation.shared`) rather than left to be inferred from the tier name,
because a shared VM and a dedicated remote builder both report `machine`.

An image built for another architecture is **refused**, not run: with Rosetta or qemu-user registered
it would otherwise execute under emulation, and an emulated build can be subtly wrong while being
attested exactly like a native one.

There is deliberately **no host-execution tier**. Every step runs with `--network none`,
`--cap-drop ALL`, a generated seccomp profile, `--userns auto`, a read-only root and no host mounts
at all — data crosses as a validated tar stream in both directions. Your `~/.ssh`, `~/.npmrc` and
environment are not reachable from a build, by construction rather than by policy.

The full argument list, what each flag buys, and the escape suite that proves it are in
[DEVELOPMENT.md](DEVELOPMENT.md#isolation).

## Platform support

| Host             | Status                                                                                 |
| ---------------- | -------------------------------------------------------------------------------------- |
| **linux-x64**    | supported and tested                                                                   |
| **linux-arm64**  | expected to work; not yet exercised                                                    |
| **darwin-arm64** | supported and tested as a HOST — runs the full suite and cross-builds all five targets |
| **darwin-x64**   | expected to work as a host; not yet exercised                                          |
| **win32**        | **not yet** — known gaps documented in [CLAUDE.md](CLAUDE.md#windows-host-support)     |

A Mac now works as a host: it runs the whole suite and cross-builds the same five targets a Linux
box does, in a Linux guest inside `podman machine`. What it does **not** yet do is the one thing only
a Mac can — produce `darwin-arm64`. That needs a darwin _execution_ tier, because a Linux container
on a Mac still cannot sign. Encouragingly the signature required is only an **ad-hoc** one
(`codesign --sign -`, from the Xcode Command Line Tools) — no certificate and no Apple ID. The
groundwork and the open design questions are in [CLAUDE.md](CLAUDE.md#macos-host-support).

The farm itself — routing `darwin-arm64` to a Mac peer over hyperdht — is designed for but not
implemented.

## Documentation

- **[DEVELOPMENT.md](DEVELOPMENT.md)** — building the images, running the tests, the isolation
  internals, and the sharp edges.
- **[CLAUDE.md](CLAUDE.md)** — design decisions and why, measured findings worth not relearning, and
  the roadmap.

## License

Apache-2.0
