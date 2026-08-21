'use strict'

// The in-sandbox agent.
//
// Runs as the container/microVM entrypoint and speaks hrpc over fd 0/1. It is the only thing
// inside the sandbox that we wrote, and it is why a multi-step job pays container setup once
// instead of once per step.
//
// Three properties it must hold, in priority order:
//
//   1. Never let a step outlive its exec stream. A build that forks and detaches would otherwise
//      keep running after the driver moved on, so every step gets its own process group and the
//      whole group is signalled -- not just the direct child.
//   2. Never merge stdout and stderr. They arrive as separately tagged frames, because a runner
//      that cannot tell a compiler warning from build output cannot classify failures later.
//   3. Never inherit the agent's own environment into a step. The step env is exactly what the
//      driver sent, which is itself an allowlist.
//
// Deliberately NOT here: any policy. The agent does not decide timeouts, limits, or what may run;
// it executes what it is told and reports faithfully. Policy lives on the trusted side, so a
// compromised agent cannot grant itself anything the sandbox did not already permit.

const { spawn } = require('bare-subprocess')
const fs = require('bare-fs')
const os = require('bare-os')

const protocol = require('../protocol.js')
const { frames, EXEC_IN } = protocol

const AGENT_VERSION = 'bw-agent/1'

// Grace period between SIGTERM and SIGKILL when stopping a step.
const KILL_GRACE_MS = 2000

// Where to look for a shell when the step names one without a slash.
//
// This exists because of the no-inherited-environment rule: the agent's own env is not passed to
// the step, so if the driver sent no PATH there is nothing to resolve `bash` against and spawn
// fails with ENOENT. Rather than quietly re-introducing ambient env, resolve against a fixed list
// of standard locations (plus the step's OWN PATH, when it sent one).
const SHELL_DIRS = ['/bin', '/usr/bin', '/usr/local/bin', '/system/bin']

function resolveShell(shell, env = {}) {
  if (!shell) shell = 'bash'
  if (shell.includes('/')) return shell // absolute or explicitly relative: use as given

  const dirs = []
  if (env.PATH) dirs.push(...env.PATH.split(':').filter(Boolean))
  dirs.push(...SHELL_DIRS)

  for (const dir of dirs) {
    const candidate = dir + '/' + shell
    try {
      fs.accessSync(candidate, fs.constants.X_OK)
      return candidate
    } catch {}
  }
  return shell // let spawn fail with a real errno rather than inventing one
}

function diag(msg) {
  // fd 2 is agent diagnostics only -- never protocol. Keeping it separate means a chatty agent
  // can never corrupt the frame stream on fd 1.
  try {
    fs.writeSync(2, `[bw-agent] ${msg}\n`)
  } catch {}
}

// Report descriptors that suggest something leaked INTO the sandbox -- an inherited host handle, a
// forwarded socket, a --preserve-fd left behind by a future refactor.
//
// "Any fd above 2" is the obvious rule and it is useless: the Bare runtime legitimately holds a
// dozen of its own (eventpoll, io_uring, eventfd, internal pipes), so that rule fires on every job
// and gets ignored, which is worse than not checking. Measured on a healthy agent: 13 internal
// descriptors, 0 suspicious.
//
// So classify instead. Anonymous kernel objects and pipes are runtime plumbing. What matters is a
// descriptor onto a real filesystem path outside the sandbox's writable tree, or any named socket
// -- a socket is how you reach podman.sock, and that is root-equivalent.
const BENIGN_FD = /^(anon_inode:|pipe:|socket:\[|\/proc\/self\/fd)/
const ALLOWED_FD_PATHS = [
  '/w/',
  '/tmp/',
  '/cache/',
  '/dev/null',
  '/dev/urandom',
  '/dev/random',
  '/proc/'
]

function strayFds() {
  const out = []
  try {
    for (const name of fs.readdirSync('/proc/self/fd')) {
      const fd = Number(name)
      if (!Number.isInteger(fd) || fd <= 2) continue
      let target = '?'
      try {
        target = fs.readlinkSync('/proc/self/fd/' + name)
      } catch {
        continue // vanished mid-scan (commonly the readdir handle itself)
      }
      if (BENIGN_FD.test(target)) continue
      // A named socket is always worth reporting, even under an allowed prefix.
      const isSocketPath = target.endsWith('.sock')
      if (!isSocketPath && ALLOWED_FD_PATHS.some((prefix) => target.startsWith(prefix))) continue
      out.push(`${fd}:${target}`)
    }
  } catch {
    // no procfs -- report nothing rather than guessing
  }
  return out
}

class Step {
  constructor(stream) {
    this.stream = stream
    this.proc = null
    this.started = false
    this.finished = false
    this.timedOut = false
    this._timer = null
    this._killTimer = null
  }

  start(frame) {
    if (this.started) {
      this._fail('exec stream received a second START frame')
      return
    }
    this.started = true

    const run = frame.run || ''
    const cwd = frame.cwd || '/w/src'

    // The step command is DATA. We hand it to a shell inside the sandbox via argv, so there is no
    // host-side string interpolation anywhere in the path and no quoting bug can escalate.
    const env = {}
    for (const pair of frame.env || []) {
      const i = pair.indexOf('=')
      if (i > 0) env[pair.slice(0, i)] = pair.slice(i + 1)
    }

    const shell = resolveShell(frame.shell, env)

    // spawn() reports a missing cwd and a missing executable with the SAME ENOENT message, which
    // sends you hunting for the wrong thing (observed: "cannot spawn /usr/bin/bash: no such file
    // or directory" when bash was present and the working directory was not). Check the cwd first
    // so the two failures are distinguishable.
    try {
      fs.statSync(cwd)
    } catch {
      this._fail(`working directory does not exist: ${cwd}`)
      return
    }

    try {
      this.proc = spawn(shell, ['-c', run], {
        cwd,
        env, //           exactly what the driver sent; nothing inherited
        stdio: ['pipe', 'pipe', 'pipe'],
        detached: true // its own process group, so we can signal the whole tree
      })
    } catch (err) {
      this._fail(`cannot spawn ${shell}: ${err.message}`)
      return
    }

    this.proc.stdout.on('data', (chunk) => this._safeWrite(frames.stdout(chunk)))
    this.proc.stderr.on('data', (chunk) => this._safeWrite(frames.stderr(chunk)))
    this.proc.on('error', (err) => this._fail(err.message))
    this.proc.on('exit', (code, signal) => this._exit(code, signal))

    if (frame.timeoutMs > 0) {
      this._timer = setTimeout(() => {
        this.timedOut = true
        diag(`step timed out after ${frame.timeoutMs}ms`)
        this.stop()
      }, frame.timeoutMs)
    }
  }

  stdin(chunk) {
    if (!this.proc || !this.proc.stdin) return
    try {
      this.proc.stdin.write(chunk)
    } catch (err) {
      diag('stdin write failed: ' + err.message)
    }
  }

  eof() {
    if (!this.proc || !this.proc.stdin) return
    try {
      this.proc.stdin.end()
    } catch {}
  }

  // Signal the process GROUP, not just the child. A build that spawned background workers would
  // otherwise leave them running after we reported the step finished.
  signal(name = 'SIGTERM') {
    if (!this.proc || this.finished) return
    try {
      os.kill(-this.proc.pid, name)
    } catch {
      try {
        this.proc.kill(name)
      } catch {}
    }
  }

  stop() {
    if (!this.proc || this.finished) return
    this.signal('SIGTERM')
    // Escalate: a step that ignores SIGTERM must not be able to hold the sandbox open.
    this._killTimer = setTimeout(() => this.signal('SIGKILL'), KILL_GRACE_MS)
  }

  _clearTimers() {
    if (this._timer) clearTimeout(this._timer)
    if (this._killTimer) clearTimeout(this._killTimer)
    this._timer = null
    this._killTimer = null
  }

  _exit(code, signal) {
    if (this.finished) return
    this.finished = true
    this._clearTimers()
    this._safeWrite(
      frames.exit({
        code: typeof code === 'number' ? code : -1,
        signal: signal || '',
        timedOut: this.timedOut
      })
    )
    this._end()
  }

  _fail(message) {
    if (this.finished) return
    this.finished = true
    this._clearTimers()
    diag('step failed: ' + message)
    this._safeWrite(frames.error(message))
    this._end()
  }

  _safeWrite(frame) {
    try {
      this.stream.write(frame)
    } catch (err) {
      diag('frame write failed: ' + err.message)
    }
  }

  _end() {
    try {
      this.stream.end()
    } catch {}
  }
}

// Create the workspace subtree.
//
// This has to happen inside the sandbox, at startup: /w is a tmpfs, so it arrives EMPTY no matter
// what the image created at build time, and the driver cannot mkdir into it from outside (there is
// no shared mount, by design). Without this, every step fails with "working directory does not
// exist: /w/src".
//
// It is layout, not policy -- the root comes from the trusted side via BW_WORKSPACE.
function ensureWorkspace(root) {
  const made = []
  for (const dir of [root, root + '/src', root + '/home', root + '/artifacts']) {
    try {
      fs.mkdirSync(dir, { recursive: true })
      made.push(dir)
    } catch (err) {
      diag(`cannot create ${dir}: ${err.message}`)
    }
  }
  return made
}

function serve(stream) {
  const rpc = protocol.createRPC(stream)

  rpc.onHello((req) => {
    diag(`hello from ${req.driver}`)
    return {
      agent: AGENT_VERSION,
      platform: os.platform(),
      arch: os.arch(),
      pid: typeof Bare !== 'undefined' && Bare.pid ? Bare.pid : 0,
      strayFds: strayFds(),
      cwd: os.cwd()
    }
  })

  rpc.onPing((req) => ({ nonce: req.nonce }))

  rpc.onExec((stream) => {
    const step = new Step(stream)
    stream.on('data', (frame) => {
      switch (frame.kind) {
        case EXEC_IN.START:
          return step.start(frame)
        case EXEC_IN.STDIN:
          return step.stdin(frame.chunk)
        case EXEC_IN.EOF:
          return step.eof()
        case EXEC_IN.SIGNAL:
          return step.signal(frame.signal || 'SIGTERM')
        default:
          diag('unknown exec frame kind: ' + frame.kind)
      }
    })
    // The driver hanging up mid-step is a cancellation, not a clean finish.
    stream.on('end', () => step.stop())
    stream.on('error', () => step.stop())
  })

  return rpc
}

module.exports = {
  serve,
  strayFds,
  resolveShell,
  ensureWorkspace,
  AGENT_VERSION,
  KILL_GRACE_MS,
  SHELL_DIRS,
  Step
}

if (require.main === module) {
  const stream = protocol.duplexFromFds(0, 1)
  serve(stream)
  diag('listening on fd 0/1')
}
