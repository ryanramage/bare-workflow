'use strict'

// Run the agent natively on macOS, confined by Seatbelt.
//
// This is the tier that exists so a Mac can produce `darwin-arm64` -- the one target a Linux runner
// cannot close, because `codesign` does not exist in a Linux guest. It is NOT a port of the podman
// launcher: there is no image, no argv builder, no container to reap. What it shares is the interface
// (`{ stream, attestation, close }`) and the protocol, which is why the transport, the framing and
// the tar-based data transfer all work here unchanged.
//
// On decision 3 ("no host-execution tier, ever"). What that decision actually argues is that "a
// command allowlist over host processes is defeated by the first `sh -c`" -- and a Seatbelt profile
// is not a command allowlist. It is kernel-enforced MAC that applies to `sh -c` and everything it
// spawns; measured, a confined build cannot read `~/.ssh/id_ed25519` however it asks. What remains
// forbidden is UNCONFINED host execution, which is why this launcher has no fallback: if the profile
// cannot be written or sandbox-exec is missing, spawning fails and the run refuses. It must never
// quietly become test/support/local-launcher.js.

const { spawn } = require('bare-subprocess')
const fs = require('bare-fs')
const path = require('bare-path')
const os = require('bare-os')

const WorkflowError = require('./../../errors.js')
const protocol = require('./../../protocol.js')
const sbpl = require('./sbpl.js')
const limits = require('./limits.js')

// Level 2 of the cancellation ladder, matching the podman launcher. Levels 3 and 4 (a container
// runtime timeout and a systemd scope) have no analogue here -- see limits.js.
const STOP_GRACE_MS = 3000

const SANDBOX_EXEC = '/usr/bin/sandbox-exec'

class SeatbeltLauncher {
  constructor(spec, opts = {}) {
    if (!spec || !spec.tier) {
      throw WorkflowError.INVALID_SPEC('SeatbeltLauncher requires a spec with a tier')
    }
    if (!spec.jobId || !/^[a-z0-9][a-z0-9-]*$/.test(spec.jobId)) {
      // Same rule as the podman jobId: it becomes a directory name, so it is validated rather than
      // sanitised. A path component built from an unvalidated id is how a job escapes its scratch.
      throw WorkflowError.INVALID_SPEC(`invalid jobId ${JSON.stringify(spec.jobId)}`)
    }

    this.spec = spec
    this.tier = spec.tier
    // bin.js, NOT index.js. The standalone entry is the one that calls `ensureWorkspace` before it
    // starts serving; index.js is a plain library whose `require.main === module` guard exists only
    // for hand-running it. Pointing at index.js gets a working handshake and then every step fails
    // with "working directory does not exist: <workspace>/src", which looks like a workspace bug
    // rather than a wrong entry point. (test/support/local-launcher.js runs index.js and gets away
    // with it because its descriptor overrides cwd to the host temp dir.)
    this.agent = spec.agent || path.join(__dirname, '../../agent/bin.js')
    this.runtime = spec.runtime || (typeof Bare !== 'undefined' ? Bare.argv[0] : 'bare')

    // One scratch tree per job, under the host temp dir. `/w` does not and must not exist here:
    // creating it would need root and would be shared between concurrent jobs.
    //
    // REALPATH, not the raw value. Seatbelt matches rules against RESOLVED paths, and on macOS
    // `os.tmpdir()` returns `/var/folders/...` which resolves to `/private/var/folders/...` -- so a
    // profile granting the unresolved form matches nothing the kernel is asked about. The agent got
    // as far as starting and then died on `os.cwd()` with "operation not permitted", inside its own
    // granted workspace.
    const root = spec.scratchRoot || (os.tmpdir ? os.tmpdir() : '/tmp')
    this.root = path.join(realpath(root), 'bw-' + spec.jobId)
    this.workspace = path.join(this.root, 'w')
    this.tmpdir = path.join(this.root, 'tmp')
    this.profilePath = path.join(this.root, 'profile.sb')

    this.limits = limits.resolve(spec.limits)

    // Two views of the same set, and the difference matters.
    //
    // ORDER IS IRRELEVANT for the profile -- a grant is a grant -- so it is sorted, which keeps the
    // generated profile diffable. ORDER IS EVERYTHING for PATH: sorting it put a stale
    // `~/.nvm/versions/node/v18.13.0/bin` ahead of `~/.volta/bin` and the build ran under node 18,
    // which CLAUDE.md records as silently failing exactly one target (`Array.prototype.with`, used
    // by bare-addon-resolve on the darwin branch). So the executable path preserves the caller's
    // order and only the profile list is sorted.
    const ordered = [...new Set(spec.toolchain || [])]
    this.toolchain = [...ordered].sort()

    // What a step can EXECUTE, derived from what the profile lets it READ, so the two cannot drift:
    // a directory a step can run from is always one it can read, and both are in the attestation.
    this.stepPath = spec.stepPath || [...ordered, '/usr/local/bin', '/usr/bin', '/bin'].join(':')

    this.proc = null
    this.stderr = ''
    this.profileSha = null
    this._closed = false

    // Declared up front so `bin.js` can record program/argv the same way it does for podman.
    this.built = {
      program: SANDBOX_EXEC,
      args: ['-f', this.profilePath, this.runtime, this.agent],
      argv: [SANDBOX_EXEC, '-f', this.profilePath, this.runtime, this.agent],
      tier: this.tier
    }
  }

  // What actually ran. The profile is the boundary for this tier, so its HASH is the load-bearing
  // field -- the equivalent of the seccomp hash and the image digest on a container tier. A path
  // alone says nothing about content, and here the content is generated per job.
  get attestation() {
    return {
      tier: this.tier,
      image: null,
      sandboxProfile: this.profilePath,
      sandboxProfileSha256: this.profileSha,
      workspace: this.workspace,
      toolchain: this.toolchain,
      limits: this.limits.applied,
      // Named explicitly rather than omitted. A limits block that lists only what worked reads as
      // though everything was applied; see limits.js.
      limitsUnenforceable: this.limits.unenforceable,
      program: this.built.program,
      argv: this.built.argv
    }
  }

  async spawn() {
    if (this.proc) throw WorkflowError.INVALID_SPEC('launcher already spawned')

    // The agent creates /w/{src,home,artifacts} itself from BW_WORKSPACE, exactly as it does in a
    // container -- but the scratch root and the tmp dir have to exist before the profile can grant
    // them, because SBPL subpath rules on a missing directory do not match once it appears.
    for (const dir of [this.root, this.workspace, this.tmpdir]) {
      fs.mkdirSync(dir, { recursive: true })
    }

    const profile = sbpl.generate({
      workspace: this.root,
      toolchain: this.toolchain
    })
    fs.writeFileSync(this.profilePath, profile)
    this.profileSha = 'sha256:' + sha256(profile)

    // No inherited environment, same invariant as every other tier. TMPDIR points INSIDE the
    // workspace on purpose: left at the host default it resolves under /private/var/folders, which
    // the profile does not grant, and npm dies on it.
    const childEnv = {
      PATH: '/usr/local/bin:/usr/bin:/bin',
      HOME: path.join(this.workspace, 'home'),
      TMPDIR: this.tmpdir,
      BW_WORKSPACE: this.workspace
    }

    try {
      this.proc = spawn(this.built.program, this.built.args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        cwd: this.root,
        env: childEnv,
        // Its own process group, so cancelling a job kills the build tree rather than just the
        // agent. The container tiers get this from the container; here it has to be asked for.
        detached: true
      })
    } catch (err) {
      throw WorkflowError.ISOLATION_UNAVAILABLE(
        `could not start ${this.built.program}: ${err.message}`
      )
    }

    this.proc.stderr.on('data', (chunk) => {
      if (this.stderr.length < 64 * 1024) this.stderr += chunk
    })

    const stream = protocol.bridge(this.proc.stdout, this.proc.stdin)

    // Surface an early exit as a stream error, or a failure to start shows up only as a handshake
    // timeout thirty seconds later, saying nothing about the cause.
    this.proc.on('exit', (code, signal) => {
      if (this._closed) return
      if (code !== 0) {
        const why = this.stderr.trim().split('\n').slice(0, 3).join(' | ') || `signal ${signal}`
        stream.destroy(
          WorkflowError.ISOLATION_UNAVAILABLE(
            `${this.built.program} exited ${code}: ${why}${explainStderr(this.stderr)}`
          )
        )
      }
    })

    return {
      stream,
      attestation: this.attestation,
      // The driver asks the launcher where the workspace is rather than assuming `/w`, which is what
      // lets the same Sandbox drive both a container and a native process.
      workspace: this.workspace,
      // The step env floor for a native tier. PATH must be the HOST's toolchain path -- the
      // container default (/usr/local/bin:/usr/bin:/bin) has no npm on a Mac, and a step dies with
      // `npm: command not found`. These are the same directories the profile grants read on and
      // that the attestation records, so what a step can execute matches what it can read.
      env: { TMPDIR: this.tmpdir, PATH: this.stepPath },
      close: (opts) => this.close(opts)
    }
  }

  async close({ force = false } = {}) {
    if (this._closed) return
    this._closed = true
    if (!this.proc) return this._cleanup()

    const proc = this.proc
    this.proc = null

    // Signal the GROUP, not the process. `detached: true` above gave the agent its own group, so a
    // negative pid reaches the build tree it spawned; killing only the agent would leave a compiler
    // running on the developer's machine. This is the native equivalent of `podman rm -f`.
    kill(proc, force ? 'SIGKILL' : 'SIGTERM')

    await new Promise((resolve) => {
      let settled = false
      const done = () => {
        if (!settled) {
          settled = true
          resolve()
        }
      }
      proc.on('exit', done)
      setTimeout(
        () => {
          kill(proc, 'SIGKILL')
          done()
        },
        force ? 250 : STOP_GRACE_MS
      )
    })

    this._cleanup()
  }

  // The scratch tree is the only thing this tier leaves on the host, so removing it is the whole of
  // teardown. Failure is swallowed deliberately: a job that cannot clean up must not also fail.
  _cleanup() {
    try {
      fs.rmSync(this.root, { recursive: true, force: true })
    } catch {}
  }
}

// Resolve symlinks so SBPL rules match what the kernel actually checks. Falls back to the input when
// the path does not exist yet -- the caller creates it immediately after.
function realpath(p) {
  try {
    return fs.realpathSync(p)
  } catch {
    return p
  }
}

function kill(proc, signal) {
  try {
    if (proc.pid) os.kill(-proc.pid, signal)
  } catch {
    try {
      proc.kill(signal)
    } catch {}
  }
}

function sha256(text) {
  const crypto = require('bare-crypto')
  return crypto.createHash('sha256').update(text).digest('hex')
}

// Two failures worth translating, both of which otherwise read as a bug in the runner.
function explainStderr(stderr) {
  if (/sandbox-exec: .*failed/i.test(stderr) || /Operation not permitted/.test(stderr)) {
    return (
      '\n  the Seatbelt profile may be too tight for this build. It denies everything by default;' +
      '\n  see what was refused with: log stream --predicate \'sender == "Sandbox"\''
    )
  }
  if (/no such file/i.test(stderr)) {
    return '\n  check that the bare runtime and the agent are readable inside the profile.'
  }
  return ''
}

function create(spec, opts) {
  return new SeatbeltLauncher(spec, opts)
}

module.exports = { SeatbeltLauncher, create, SANDBOX_EXEC }
