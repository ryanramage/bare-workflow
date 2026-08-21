# bare-workflow

A P2P build farm for Holepunch, running sandboxed workflows on [Bare](https://github.com/holepunchto/bare).

> [!NOTE]
> This is an experimental library, and early. A version 1.0.0 release will signal stability.
> Today it parses a workflow and runs one job's steps inside a microVM. The job DAG, matrix
> expansion, artifacts, and the P2P farm are not built yet.

```console
$ bare-workflow run examples/hello.yml
◉ hello  tier=microvm  image=bare-workflow-base:dev
  ◉ echo "hello from inside the sandbox"
    hello from inside the sandbox
  ✔ echo "hello from inside the sandbox"  32ms
  ◉ uname -r
    6.12.91
  ✔ uname -r  34ms
  ✔ job main: success
```

That `6.12.91` is the guest kernel, not the host's — the step really ran inside the VM.

## Why

`pear build` does not compile anything — it assembles already-built per-platform bundles into
`<target>/by-arch/<plat-arch>/app/<Name>`. Producing those inputs means running `bare-make` /
`npm run make` on a machine of that OS, with that OS's signing chain. Emulation cannot fix that,
so a farm of heterogeneous _real_ peers is the answer, and every job has to be safe to run on
someone else's machine.

That last part is the hard part, and it is what exists so far.

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

## CLI

```
bare-workflow validate <file>   # parse and report; exit 1 on a bad workflow
bare-workflow run <file>        # run it in the strongest available sandbox
bare-workflow doctor            # what tiers and targets this host supports
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
