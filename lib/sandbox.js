'use strict'

// Driver-side sandbox handle: prepare once, exec many, dispose.
//
// The prepare/exec/dispose split is the point. wrkflw creates a container per step, so a ten-step
// job pays image resolution and container setup ten times; here a job pays it once and each step
// costs one protocol frame. It is also forced on us: a krun microVM cannot be `podman exec`'d, so
// there is no per-step re-entry available even if we wanted it.
//
// Streaming, not collecting. wrkflw reads logs after the container exits, which means a build that
// hangs at 95% shows you nothing and a build that prints 10 GB either OOMs the runner or fills the
// host journal. Output here arrives as it happens, with byte and rate caps enforced by the driver.
//
// The `launcher` argument is how a sandbox stays testable: it is the only thing that knows how to
// start an agent. Production launchers live in lib/isolation/; tests inject a launcher that runs
// the agent as a plain subprocess. Nothing in this file knows what a container is.

const { PassThrough } = require('bare-stream')
const EventEmitter = require('bare-events')

const protocol = require('./protocol.js')
const transfer = require('./transfer.js')
const WorkflowError = require('./errors.js')
const { EXEC_OUT, GET_OUT } = protocol

const DEFAULTS = {
  logBytes: 64 * 1024 * 1024, // per step
  helloTimeoutMs: 30000
}

// The floor of every step environment. The workload's env is an allowlist, but an EMPTY allowlist
// is not a security win -- it just means `bash` cannot be resolved and every step dies with ENOENT.
// These mirror what the argv builder puts on the container itself; a step may override any of them.
const BASE_ENV = {
  PATH: '/usr/local/bin:/usr/bin:/bin',
  HOME: '/w/home',
  TMPDIR: '/tmp',
  CI: 'true'
}

// Where a step writes `key=value` lines for later steps and jobs to read.
//
// A FILE, not stdout scraping. GHA's `::set-output::` reads the log, which means ordinary build
// output can forge an output and an untrusted build can spoof anything -- in a P2P farm, where log
// lines are attacker-controlled by construction, that is not a defensible design. A file descriptor
// is a capability; stdout is a broadcast.
const OUTPUT_ENV = 'BW_OUTPUT'

class StepRun extends EventEmitter {
  constructor(duplex, { logBytes, stepTimeoutMs, signal }) {
    super()
    this._duplex = duplex
    this._logBytes = logBytes
    this._bytesOut = 0

    this.stdout = new PassThrough()
    this.stderr = new PassThrough()

    this.startedAt = Date.now()
    this.endedAt = null
    this.truncated = false
    this.cancelled = false
    this.cancelReason = null
    this.timedOut = false

    this._settled = false
    this._resolve = null
    this._result = new Promise((resolve) => {
      this._resolve = resolve
    })

    // Driver-side timeout, independent of the agent's own timer. Two layers because the agent
    // could be wedged, and a wedged agent must not be able to hold a job open forever.
    this._timer = null
    if (stepTimeoutMs > 0) {
      this._timer = setTimeout(() => this.cancel('timeout'), stepTimeoutMs)
    }

    if (signal) onAbort(signal, () => this.cancel('user'))

    duplex.on('data', (frame) => this._onFrame(frame))
    duplex.on('error', (err) => this._settle({ code: -1, error: err.message }))
    // The stream ending without a terminal frame means the agent died mid-step.
    duplex.on('end', () => this._settle({ code: -1, error: 'agent closed the exec stream' }))
    // 'close' without 'end' happens when the transport is torn down under us (the sandbox was
    // disposed, the launcher killed the agent). Without this, wait() hangs forever -- which is
    // strictly worse than a failure, because a caller awaiting it never gets control back.
    duplex.on('close', () => this._settle({ code: -1, error: 'exec stream closed' }))
  }

  get bytesOut() {
    return this._bytesOut
  }

  _onFrame(frame) {
    switch (frame.kind) {
      case EXEC_OUT.STDOUT:
        return this._output(this.stdout, frame.chunk)
      case EXEC_OUT.STDERR:
        return this._output(this.stderr, frame.chunk)
      case EXEC_OUT.EXIT: {
        this.timedOut = this.timedOut || !!frame.timedOut
        // Parse here, on the trusted side: the file was written by the workload.
        const parsed = protocol.parseOutputs(frame.outputsRaw || '')
        return this._settle({
          code: frame.code,
          signal: frame.signal || null,
          outputs: parsed.outputs,
          outputErrors: parsed.errors,
          outputsTruncated: !!frame.outputsTruncated
        })
      }
      case EXEC_OUT.ERROR:
        return this._settle({ code: -1, error: frame.message })
      default:
        this.emit('warning', 'unknown response frame kind: ' + frame.kind)
    }
  }

  _output(target, chunk) {
    if (!chunk || this.truncated) return
    this._bytesOut += chunk.byteLength

    if (this._logBytes > 0 && this._bytesOut > this._logBytes) {
      // A runaway log is a denial-of-service on the runner, not just noise. Stop the step rather
      // than buffering or silently dropping -- and record that we did, so a truncated log is never
      // mistaken for a complete one.
      this.truncated = true
      target.write(chunk)
      this.emit('truncated', { bytesOut: this._bytesOut, limit: this._logBytes })
      this.cancel('log-limit')
      return
    }
    target.write(chunk)
  }

  // Settle immediately without waiting for the agent. Used when the transport is gone, so there
  // is nobody left to report an exit -- wait() must still resolve.
  abandon(reason = 'abandoned') {
    if (this._settled) return
    this.cancelled = true
    this.cancelReason = this.cancelReason || reason
    this._settle({ code: -1, error: reason })
  }

  // Ask the agent to stop the step. Level 1 of the cancellation ladder; the driver's own kill and
  // podman's --timeout sit behind it for the case where the agent does not comply.
  cancel(reason = 'user') {
    if (this._settled) return
    if (!this.cancelled) {
      this.cancelled = true
      this.cancelReason = reason
      if (reason === 'timeout') this.timedOut = true
      this.emit('cancel', reason)
    }
    try {
      this._duplex.write(protocol.frames.signal('SIGTERM'))
    } catch {}
  }

  write(chunk) {
    try {
      this._duplex.write(protocol.frames.stdin(chunk))
    } catch (err) {
      this.emit('warning', 'stdin write failed: ' + err.message)
    }
  }

  end() {
    try {
      this._duplex.write(protocol.frames.eof())
    } catch {}
  }

  async wait() {
    return this._result
  }

  _settle(partial) {
    if (this._settled) return
    this._settled = true
    if (this._timer) clearTimeout(this._timer)
    this.endedAt = Date.now()

    try {
      this.stdout.end()
    } catch {}
    try {
      this.stderr.end()
    } catch {}
    try {
      this._duplex.end()
    } catch {}

    const result = {
      code: partial.code,
      signal: partial.signal || null,
      error: partial.error || null,
      outputs: partial.outputs || {},
      outputErrors: partial.outputErrors || [],
      outputsTruncated: !!partial.outputsTruncated,
      timedOut: this.timedOut,
      cancelled: this.cancelled,
      cancelReason: this.cancelReason,
      truncated: this.truncated,
      bytesOut: this._bytesOut,
      startedAt: this.startedAt,
      endedAt: this.endedAt,
      ms: this.endedAt - this.startedAt
    }
    this.emit('exit', result)
    this._resolve(result)
  }
}

class Sandbox extends EventEmitter {
  constructor(opts = {}) {
    if (!opts.launcher) throw WorkflowError.INVALID_SPEC('Sandbox requires a launcher')
    super()
    this.launcher = opts.launcher
    this.logBytes = opts.logBytes ?? DEFAULTS.logBytes
    this.helloTimeoutMs = opts.helloTimeoutMs ?? DEFAULTS.helloTimeoutMs
    this.allowStrayFds = opts.allowStrayFds === true

    this.tier = null
    this.hello = null
    this.attestation = null
    this._rpc = null
    this._handle = null
    this._prepared = false
    this._disposed = false
    this._runs = new Set()
  }

  async prepare() {
    if (this._prepared) return this
    if (this._disposed) throw WorkflowError.INVALID_SPEC('sandbox already disposed')

    this._handle = await this.launcher.spawn()
    this._rpc = protocol.createRPC(this._handle.stream)
    this.tier = this.launcher.tier || null
    this.attestation = this._handle.attestation || null

    const hello = await this._withTimeout(
      this._rpc.hello({ driver: 'bare-workflow/1' }),
      this.helloTimeoutMs,
      'agent did not complete the hello handshake'
    )
    this.hello = hello

    // A descriptor onto a host path, or any named socket, means something leaked into the
    // sandbox. Refuse the job rather than run a workload next to an inherited handle.
    if (hello.strayFds && hello.strayFds.length && !this.allowStrayFds) {
      await this.dispose()
      throw WorkflowError.ISOLATION_UNAVAILABLE(
        'agent reported descriptors leaked into the sandbox: ' + hello.strayFds.join(', ')
      )
    }

    // An older agent reports no command list at all; treat that as "core only" rather than
    // assuming it can do everything this driver knows how to ask for.
    this.commands =
      hello.commands && hello.commands.length ? hello.commands : ['hello', 'ping', 'exec']

    this._prepared = true
    this.emit('ready', hello)
    return this
  }

  async ping(nonce = 1) {
    this._assertReady()
    const res = await this._rpc.ping({ nonce })
    return res.nonce === nonce
  }

  // Cheap: one frame, no container setup. This is what the prepare/exec split buys.
  exec(step, opts = {}) {
    this._assertReady()
    const duplex = this._rpc.exec()
    const run = new StepRun(duplex, {
      logBytes: opts.logBytes ?? this.logBytes,
      stepTimeoutMs: opts.timeoutMs ?? 0,
      signal: opts.signal
    })
    this._runs.add(run)
    run.once('exit', () => this._runs.delete(run))

    duplex.write(
      protocol.frames.start({
        run: step.run,
        shell: step.shell || 'bash',
        cwd: step.cwd || '/w/src',
        env: toEnvPairs({
          ...BASE_ENV,
          [OUTPUT_ENV]: (opts.workspace || '/w') + '/' + protocol.OUTPUT_FILE,
          ...(step.env || {})
        }),
        // Let the agent enforce it too, so a wedged driver is not the only brake.
        timeoutMs: opts.timeoutMs ?? 0
      })
    )
    return run
  }

  // Stream a local directory into the sandbox.
  //
  // A copy, not a mount. Rootless idmapped bind mounts are kernel-forbidden and we refuse host
  // mounts on principle, so this is the only way in -- and the upside is that no host path ever
  // exists inside the sandbox, which deletes both the bind-mount attack surface and the
  // host-path-rebasing problem wrkflw needs a whole subsystem for.
  async put(localPath, sandboxPath, opts = {}) {
    this._assertReady()
    this._assertSupports('put')
    const stream = this._rpc.put()
    const packer = transfer.pack(localPath, opts)

    stream.write(protocol.frames.putStart(sandboxPath))

    await new Promise((resolve, reject) => {
      packer.on('data', (chunk) => stream.write(protocol.frames.putChunk(chunk)))
      packer.on('error', reject)
      packer.on('end', () => {
        stream.write(protocol.frames.putEnd())
        resolve()
      })
    })

    const reply = await stream.reply()
    if (!reply.ok) {
      throw WorkflowError.TRANSFER_REJECTED(`put ${sandboxPath} failed: ${reply.message}`)
    }
    return { files: reply.files, bytes: reply.bytes, skipped: packer.stats.skipped }
  }

  // Stream a path out of the sandbox into a fresh local directory.
  //
  // The archive was produced by the workload's filesystem, so it is validated on arrival -- see
  // lib/transfer.js for what that rejects and why.
  async get(sandboxPath, localPath, opts = {}) {
    this._assertReady()
    this._assertSupports('get')
    const dest = transfer.freshDir(localPath)
    const stream = this._rpc.get({ path: sandboxPath, globs: opts.globs || [] })

    const { Readable } = require('bare-stream')
    const incoming = new Readable()
    let failure = null
    let counts = { files: 0, bytes: 0 }

    stream.on('data', (frame) => {
      if (frame.kind === GET_OUT.CHUNK) return incoming.push(frame.chunk)
      if (frame.kind === GET_OUT.DONE) {
        counts = { files: frame.files, bytes: frame.bytes }
        return incoming.push(null)
      }
      if (frame.kind === GET_OUT.ERROR) {
        failure = WorkflowError.TRANSFER_REJECTED(`get ${sandboxPath} failed: ${frame.message}`)
        return incoming.push(null)
      }
    })
    stream.on('end', () => incoming.push(null))

    const extracted = await transfer.extract(incoming, dest, opts)
    if (failure) throw failure
    return { ...extracted, reported: counts, dest }
  }

  async dispose({ force = false } = {}) {
    if (this._disposed) return
    this._disposed = true
    this._prepared = false

    const inflight = [...this._runs]
    for (const run of inflight) {
      try {
        run.cancel('disposed')
      } catch {}
    }

    try {
      if (this._handle) await this._handle.close({ force })
    } catch (err) {
      this.emit('warning', 'launcher close failed: ' + err.message)
    }

    // The agent is gone now, so nothing will ever send a terminal frame for these. Settle them
    // ourselves rather than leaving a caller awaiting wait() forever.
    for (const run of inflight) {
      try {
        run.abandon('sandbox disposed')
      } catch {}
    }
    this._runs.clear()
    this.emit('disposed')
  }

  // Refuse clearly rather than calling into an agent that has no handler for the command. Without
  // this the agent crashes and the driver reports "podman exited 139", which says nothing about the
  // actual problem -- observed exactly once, which was enough.
  _assertSupports(command) {
    if (this.commands && !this.commands.includes(command)) {
      throw WorkflowError.AGENT_TOO_OLD(
        `the agent in this image does not implement ${JSON.stringify(command)} ` +
          `(it advertises: ${this.commands.join(', ')}). Rebuild the sandbox image: bare scripts/build/agent.js`
      )
    }
  }

  _assertReady() {
    if (this._disposed) throw WorkflowError.INVALID_SPEC('sandbox has been disposed')
    if (!this._prepared) throw WorkflowError.INVALID_SPEC('call prepare() before exec()')
  }

  async _withTimeout(promise, ms, message) {
    if (!ms) return promise
    let timer
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(WorkflowError.ISOLATION_UNAVAILABLE(message)), ms)
        })
      ])
    } finally {
      clearTimeout(timer)
    }
  }
}

// Accept either cancellation shape. Bare has no AbortController/AbortSignal/EventTarget at all,
// so requiring a web AbortSignal here would force a dependency on every caller; and requiring an
// EventEmitter would break Node callers who already have a signal. Support both and let the caller
// use whatever their runtime gives them.
function onAbort(signal, fn) {
  if (!signal) return
  if (signal.aborted) return fn()

  if (typeof signal.addEventListener === 'function') {
    signal.addEventListener('abort', fn, { once: true }) // web AbortSignal
    return
  }
  if (typeof signal.once === 'function') {
    signal.once('abort', fn) // EventEmitter -- the idiomatic Bare shape
    return
  }
  throw WorkflowError.INVALID_SPEC(
    'signal must be an AbortSignal or an EventEmitter emitting "abort"'
  )
}

function toEnvPairs(env) {
  if (!env) return []
  if (Array.isArray(env)) return env
  return Object.keys(env)
    .sort()
    .map((k) => `${k}=${env[k]}`)
}

function create(opts) {
  return new Sandbox(opts)
}

module.exports = { Sandbox, StepRun, create, toEnvPairs, onAbort, DEFAULTS, BASE_ENV, OUTPUT_ENV }
