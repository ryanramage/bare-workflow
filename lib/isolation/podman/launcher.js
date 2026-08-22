'use strict'

// Podman launcher: starts an agent inside a real sandbox and hands back its duplex.
//
// This is the piece that joins the two halves of the project. Until now the escape suite proved
// the isolation posture holds, and the Sandbox lifecycle tests proved the protocol works -- but
// they proved it against a host subprocess. With this launcher the SAME lifecycle tests run inside
// a hardened container or a krun microVM, so "the sandbox holds" and "the runner works" become one
// story instead of two hopeful halves.
//
// It is deliberately thin. Everything about the isolation posture lives in argv.js (pure, snapshot
// tested); everything about the protocol lives in protocol.js. This file only spawns, bridges, and
// tears down.

const { spawn } = require('bare-subprocess')
const env = require('bare-env')

const argvlib = require('./argv.js')
const protocol = require('../../protocol.js')
const WorkflowError = require('../../errors.js')

// How long to wait for a container to die politely before escalating. Level 2 of the cancellation
// ladder (level 1 is the agent signalling its own step; 3 and 4 are podman --timeout and the
// systemd scope).
const STOP_GRACE_MS = 3000

class PodmanLauncher {
  constructor(spec, opts = {}) {
    if (!spec || !spec.tier) {
      throw WorkflowError.INVALID_SPEC('PodmanLauncher requires a spec with a tier')
    }
    this.spec = spec
    this.tier = spec.tier
    this.built = argvlib.build(spec)
    this.hostEnv = argvlib.requiredHostEnv(spec, opts.hostEnv || env)
    this.proc = null
    this.stderr = ''
    this._closed = false
  }

  // What actually ran, for the job record. The image digest, the seccomp hash and the exact argv
  // are the three things you need to reproduce or audit a build after the fact.
  get attestation() {
    return {
      tier: this.tier,
      image: `${this.spec.image.ref}@${this.spec.image.digest}`,
      seccompProfile: this.spec.seccompProfile || null,
      program: this.built.program,
      argv: this.built.argv
    }
  }

  async spawn() {
    if (this.proc) throw WorkflowError.INVALID_SPEC('launcher already spawned')

    this.proc = spawn(this.built.program, this.built.args, {
      // Protocol on 0/1, diagnostics on 2 -- the shape test/fidelity.js proved byte-exact and
      // backpressured under the hardened flag set.
      stdio: ['pipe', 'pipe', 'pipe'],
      env: this.hostEnv
    })

    this.proc.stderr.on('data', (chunk) => {
      // Cap it: a failing podman invocation can be chatty, and this buffer is on the trusted side.
      if (this.stderr.length < 64 * 1024) this.stderr += chunk
    })

    const stream = protocol.bridge(this.proc.stdout, this.proc.stdin)

    // Surface an early exit as a stream error. Without this a container that fails to start (bad
    // flag, missing image, krun unavailable) shows up only as a handshake timeout, which tells you
    // nothing about the real cause.
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
      close: (opts) => this.close(opts)
    }
  }

  async close({ force = false } = {}) {
    if (this._closed) return
    this._closed = true
    if (!this.proc) return

    const proc = this.proc
    this.proc = null

    // Ask the client process to stop, then escalate. `podman run --rm` tears the container down
    // with it; the cidfile-based kill below is the backstop for when the client is already gone.
    try {
      proc.kill(force ? 'SIGKILL' : 'SIGTERM')
    } catch {}

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
          try {
            proc.kill('SIGKILL')
          } catch {}
          done()
        },
        force ? 250 : STOP_GRACE_MS
      )
    })

    // Level 2: the container can outlive the client that started it, so name it explicitly.
    await this._reap()
  }

  async _reap() {
    const name = 'bw-' + this.spec.jobId
    await new Promise((resolve) => {
      let proc
      try {
        proc = spawn('podman', ['rm', '-f', '--ignore', name], {
          stdio: ['ignore', 'ignore', 'ignore'],
          env: this.hostEnv
        })
      } catch {
        return resolve()
      }
      proc.on('error', () => resolve())
      proc.on('exit', () => resolve())
      setTimeout(resolve, 5000)
    })
  }
}

function create(spec, opts) {
  return new PodmanLauncher(spec, opts)
}

// Turn two podman failures that are genuinely confusing into ones that name their real cause. Both
// are the same shape: podman reports a fact about the machine it talks to, and the message reads as
// nonsense on the machine you are sitting at.
function explainStderr(stderr) {
  // The seccomp profile is an absolute HOST path, but the podman service reads it off ITS OWN
  // filesystem. On Linux those are the same filesystem. On macOS and Windows the service lives
  // inside a VM, so the path has to be visible in the guest too.
  //
  // Measured on macOS: podman machine mounts /Users and /private via virtiofs, so a repo cloned
  // under either resolves fine -- which is why this is invisible for most people. /Volumes is NOT
  // mounted, so a clone there fails with "no such file or directory" naming a path that plainly
  // exists on the host. podman fails closed rather than falling back to a permissive default (also
  // measured), so this is a loud blocker and never a silent security regression.
  if (/opening seccomp profile failed/i.test(stderr)) {
    return (
      '\n  the seccomp profile is read by the podman SERVICE, not by this process. On macOS and ' +
      'Windows that service runs inside a Linux VM, which only sees some host paths (on macOS: ' +
      '/Users and /private). Move the checkout somewhere the VM mounts, or pass a profile path ' +
      'that resolves inside the guest.'
    )
  }
  // An agent built for the wrong architecture. podman reports 126 with almost nothing, which reads
  // as a launcher bug rather than an architecture one.
  if (/exec format error/i.test(stderr)) {
    return (
      '\n  that is an architecture mismatch: the baked agent was built for a different arch than ' +
      'the podman server runs. Rebuild with: bare scripts/build/agent.js'
    )
  }
  return ''
}

module.exports = { PodmanLauncher, create, STOP_GRACE_MS }
