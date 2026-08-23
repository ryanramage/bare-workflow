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

const { spawn, spawnSync } = require('bare-subprocess')
const fs = require('bare-fs')
const os = require('bare-os')
const { which } = require('../host-env.js')

const protocol = require('../protocol.js')
const transfer = require('../transfer.js')

// Glob engine for `get`, loaded with a LITERAL specifier.
//
// This must not be `require(someVariable)`: bare-build's standalone bundler resolves requires
// statically, so a dynamic specifier is invisible to it and the module simply is not in the
// binary. That produced a genuinely confusing failure -- an `out/**` artifact came back empty on a
// freshly rebuilt image, because the agent had silently fallen back to matching nothing.
let picomatch = null
try {
  picomatch = require('picomatch')
} catch {
  picomatch = null
}
const { frames, EXEC_IN, PUT_IN } = protocol

const AGENT_VERSION = 'bw-agent/1'

// What this agent implements. Advertised in the hello response so a newer driver can refuse cleanly
// instead of calling a command an older agent would crash on.
const COMMANDS = ['hello', 'ping', 'exec', 'put', 'get']

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

// Whether the scan RAN, separately from what it found.
//
// This used to be one function returning an array, with `catch {}` around the procfs read and the
// comment "no procfs -- report nothing rather than guessing". That made "I looked and found nothing"
// indistinguishable from "I could not look", and on macOS -- which has no /proc at all -- the
// fd-leak detector reported clean for every process, forever, including in the assertion whose whole
// job is to catch a leak. A security control that degrades silently is precisely what decision 4
// forbids, and this one degraded to always-pass.
//
// The agent runs inside a Linux guest on every tier that exists today, so 'ok' is the only answer
// anyone should ever see in production. It becomes load bearing the moment a darwin-native tier
// exists, and it is what lets the tests refuse to pretend on a Mac in the meantime.
const FD_SCAN_OK = 'ok'

function scanFds() {
  if (os.platform() === 'darwin') return scanFdsDarwin()
  return scanFdsProc()
}

function scanFdsProc() {
  let names
  try {
    names = fs.readdirSync('/proc/self/fd')
  } catch (err) {
    return {
      status: `unsupported: cannot read /proc/self/fd on ${os.platform()} (${err.code || err.message})`,
      fds: []
    }
  }

  const out = []
  for (const name of names) {
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
  return { status: FD_SCAN_OK, fds: out }
}

// --- darwin -----------------------------------------------------------------------------
//
// macOS has no procfs, and the obvious substitute does not work: `/dev/fd` lists descriptor NUMBERS
// but does not resolve to paths. `readlink /dev/fd/9` returns nothing, and `realpath` leaks only the
// basename (`/dev/fd/hosts`) -- measured. So this cannot be the Linux scan with the directory
// swapped, and the two halves are obtained separately:
//
//   * `lsof -p <pid> -F ftn` gives type AND path for every descriptor in one call. That is the
//     primary source: it has the same fidelity as reading /proc, including for directory handles,
//     which the fallback below cannot classify at all.
//   * If lsof is unavailable, fall back to enumerating /dev/fd and classifying each descriptor by
//     `fstat` TYPE alone. That is weaker -- it cannot tell a leaked host directory from the runtime's
//     own -- so it reports a DEGRADED status rather than 'ok', and an isolated tier requiring 'ok'
//     will refuse. Reporting a weaker scan as a clean one is the exact failure this whole field
//     exists to prevent.
//
// One call at startup, not one per descriptor: hello happens once per sandbox, and the alternative
// (lsof only for already-suspicious fds) cannot see the directory case at all.
// lsof names for anonymous kernel objects: `->0x<pointer>` for pipes and sockets, `count=N, state=…`
// for kqueues. The direct equivalent of procfs's `anon_inode:` / `pipe:[N]` / `socket:[N]`, which
// BENIGN_FD above already treats as plumbing. Getting this mapping wrong in the obvious direction is
// what the first version did -- it treated lsof type `unix` as always-reportable, which flagged
// Bare's own runtime sockets on every startup and would have made the sandbox refuse to start every
// time. A control that fires constantly is as useless as one that never fires.
const DARWIN_ANON_NAME = /^(->0x[0-9a-f]+|count=)/

const DARWIN_BENIGN_TYPES = new Set([
  'FIFO',
  'PIPE',
  'CHR',
  'KQUEUE',
  'NPOLICY',
  'systm',
  'unknown'
])

function scanFdsDarwin() {
  const viaLsof = darwinLsofFds()
  if (viaLsof) return { status: FD_SCAN_OK, fds: viaLsof }

  // Fallback: type-only classification from /dev/fd + fstat.
  //
  // Measured baseline for a Bare agent spawned with stdio ['pipe','pipe','pipe']:
  //   3:fifo 4:fifo 5:fifo 6:dir 7:fifo 8:dir 9:fifo 10:fifo
  // and a descriptor leaked in as an extra stdio entry appears as `3:reg`. So a regular file or a
  // socket above fd 2 is a real finding, while fifos and directories are runtime plumbing. The
  // directory case is precisely what makes this weaker than lsof: a leaked HOST directory is also
  // `dir`, and this cannot tell them apart.
  const S_IFMT = 0o170000
  const TYPES = {
    0o010000: 'fifo',
    0o020000: 'chr',
    0o040000: 'dir',
    0o060000: 'blk',
    0o100000: 'reg',
    0o120000: 'lnk',
    0o140000: 'sock'
  }
  let names
  try {
    names = fs.readdirSync('/dev/fd')
  } catch (err) {
    return {
      status: `unsupported: no lsof and cannot read /dev/fd (${err.code || err.message})`,
      fds: []
    }
  }

  const out = []
  for (const name of names) {
    const fd = Number(name)
    if (!Number.isInteger(fd) || fd <= 2) continue
    let type
    try {
      type = TYPES[fs.fstatSync(fd).mode & S_IFMT] || 'unknown'
    } catch {
      continue // vanished mid-scan -- commonly this readdir's own handle
    }
    if (type === 'reg' || type === 'sock') out.push(`${fd}:<${type}, path unavailable>`)
  }
  return {
    status:
      'degraded: lsof unavailable, descriptors classified by type only -- ' +
      'a leaked directory handle cannot be distinguished from runtime plumbing',
    fds: out
  }
}

// `lsof -F ftn` emits one field per line: `f<fd>`, `t<TYPE>`, `n<NAME>`, grouped per descriptor.
// Returns null when lsof cannot be used at all, so the caller can fall back and say so.
// Known absolute locations, tried when PATH cannot resolve it.
//
// This is the same problem `resolveShell` solves a few lines up, for the same reason: the agent runs
// with NO inherited environment, so a step -- or the agent itself -- may have no PATH at all. Without
// this the scan silently degraded to type-only classification in exactly the place it matters, and
// said so honestly, which is better than lying but is still not a working control. lsof ships with
// macOS at /usr/sbin/lsof.
const LSOF_PATHS = ['/usr/sbin/lsof', '/usr/bin/lsof', '/opt/homebrew/bin/lsof']

function darwinLsofFds() {
  let lsof = which('lsof')
  if (!lsof) {
    for (const candidate of LSOF_PATHS) {
      try {
        fs.statSync(candidate)
        lsof = candidate
        break
      } catch {}
    }
  }
  if (!lsof) return null

  const pid = typeof Bare !== 'undefined' && Bare.pid ? Bare.pid : 0
  if (!pid) return null

  let r
  try {
    r = spawnSync(lsof, ['-p', String(pid), '-F', 'ftn'], { env: {} })
  } catch {
    return null
  }
  // lsof exits non-zero when some descriptors could not be described; it still prints the rest, so
  // the output is used whenever there is any. Only a total absence of output is a real failure.
  const text = r && r.stdout ? r.stdout.toString() : ''
  if (!text) return null

  const out = []
  let fd = null
  let type = null
  for (const raw of text.split('\n')) {
    if (!raw) continue
    const tag = raw[0]
    const value = raw.slice(1)
    if (tag === 'f') {
      fd = /^\d+$/.test(value) ? Number(value) : null
      type = null
    } else if (tag === 't') {
      type = value
    } else if (tag === 'n' && fd !== null && fd > 2) {
      if (!benignDarwinFd(type, value)) out.push(`${fd}:${value}`)
      fd = null
    }
  }
  return out
}

// The darwin equivalent of ALLOWED_FD_PATHS. Deliberately short: a native tier's workspace is a
// per-job scratch directory supplied by the launcher, and anything outside it is a finding.
const DARWIN_ALLOWED_FD_PATHS = ['/dev/null', '/dev/random', '/dev/urandom']

function benignDarwinFd(type, name) {
  if (DARWIN_BENIGN_TYPES.has(type)) return true
  if (DARWIN_ANON_NAME.test(name)) return true

  // Bare's runtime holds open directory handles on `/` -- measured, present in every process, so
  // reporting them would make this control fire on every startup and be switched off. Narrow on
  // purpose: a directory handle onto ANYWHERE ELSE is still a finding, because that is what a leaked
  // host directory looks like. Less dangerous here than the Linux equivalent would be: there is no
  // chroot to escape, and Seatbelt mediates operations performed THROUGH a descriptor, not just the
  // open that produced it.
  if (type === 'DIR' && name === '/') return true

  // A named socket is always a finding, whatever prefix it sits under -- reaching a daemon's socket
  // is root-equivalent and is the single most valuable thing this check can catch.
  if (name.endsWith('.sock')) return false

  return DARWIN_ALLOWED_FD_PATHS.some((prefix) => name.startsWith(prefix))
}

// The list alone, for callers that already know the scan ran. Note this deliberately CANNOT report
// "unsupported": an empty array from here means nothing on its own, which is the whole point of
// keeping scanFds().status next to it.
function strayFds() {
  return scanFds().fds
}

class Step {
  constructor(stream) {
    this.stream = stream
    this.proc = null
    this.started = false
    this.finished = false
    this.timedOut = false
    this.outputPath = null
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

    // The driver tells us where the output file is via BW_OUTPUT; the agent never invents the
    // location, so the trusted side stays in control of the workspace layout.
    this.outputPath = env.BW_OUTPUT || null
    if (this.outputPath) {
      // Create it empty so a step can append without checking, and so a leftover file from a
      // previous step can never be misread as this step's output.
      try {
        fs.writeFileSync(this.outputPath, '')
      } catch (err) {
        diag(`cannot prepare output file ${this.outputPath}: ${err.message}`)
      }
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

  // Read the step's output file, ship it verbatim, then truncate it so the next step starts clean.
  //
  // Truncating per step is the rule wrkflw settled on and it matters: without it, step 5 inherits
  // step 2's outputs and a stale value looks like a live one. Nothing is parsed here -- the content
  // is attacker-controlled and the trusted side owns the one parser.
  _drainOutputs() {
    if (!this.outputPath) return { outputsRaw: '', outputsTruncated: false }
    let raw = ''
    let truncated = false
    try {
      const stat = fs.statSync(this.outputPath)
      if (stat.size > protocol.OUTPUT_MAX_BYTES) {
        // A build can write an arbitrarily large file here; read a bounded prefix and say so
        // rather than pulling it all into memory.
        const fd = fs.openSync(this.outputPath, 'r')
        try {
          const buf = Buffer.alloc(protocol.OUTPUT_MAX_BYTES)
          const read = fs.readSync(fd, buf, 0, protocol.OUTPUT_MAX_BYTES, 0)
          raw = buf.subarray(0, read).toString()
        } finally {
          fs.closeSync(fd)
        }
        truncated = true
      } else if (stat.size > 0) {
        raw = fs.readFileSync(this.outputPath, 'utf8')
      }
    } catch {
      // No file means the step wrote no outputs, which is the common case.
    }
    try {
      fs.writeFileSync(this.outputPath, '')
    } catch {}
    return { outputsRaw: raw, outputsTruncated: truncated }
  }

  _exit(code, signal) {
    if (this.finished) return
    this.finished = true
    this._clearTimers()
    const { outputsRaw, outputsTruncated } = this._drainOutputs()
    this._safeWrite(
      frames.exit({
        code: typeof code === 'number' ? code : -1,
        signal: signal || '',
        timedOut: this.timedOut,
        outputsRaw,
        outputsTruncated
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
  for (const dir of [
    root,
    root + '/src',
    root + '/home',
    root + '/artifacts',
    root + '/.bare-workflow'
  ]) {
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
    const scan = scanFds()
    return {
      agent: AGENT_VERSION,
      platform: os.platform(),
      arch: os.arch(),
      pid: typeof Bare !== 'undefined' && Bare.pid ? Bare.pid : 0,
      strayFds: scan.fds,
      fdScan: scan.status,
      cwd: os.cwd(),
      commands: COMMANDS
    }
  })

  rpc.onPing((req) => ({ nonce: req.nonce }))

  // put: the driver streams a tar in, we extract it.
  //
  // hrpc shape note, learned by getting it wrong: for a streaming REQUEST with a single response,
  // the handler must RETURN the reply object -- the generated dispatcher calls req.reply() with
  // whatever it returns. Writing to the stream does nothing.
  rpc.onPut(async (stream) => {
    const { Readable } = require('bare-stream')
    // Push chunks through as they arrive rather than buffering the archive: an artifact can be
    // hundreds of megabytes and the agent has a memory limit like everything else.
    const incoming = new Readable()
    let dest = null
    let sawStart = false

    const extraction = new Promise((resolve) => {
      let settled = false
      const finish = (value) => {
        if (!settled) {
          settled = true
          resolve(value)
        }
      }

      stream.on('data', (frame) => {
        if (frame.kind === PUT_IN.START) {
          dest = frame.path
          sawStart = true
          try {
            fs.mkdirSync(dest, { recursive: true })
          } catch (err) {
            diag(`put: cannot create ${dest}: ${err.message}`)
          }
          transfer
            .extract(incoming, dest)
            .then((r) => finish({ ok: true, files: r.files, bytes: r.bytes, message: '' }))
            .catch((err) => {
              diag('put failed: ' + err.message)
              finish({ ok: false, files: 0, bytes: 0, message: err.message })
            })
          return
        }
        if (frame.kind === PUT_IN.CHUNK) {
          if (frame.chunk) incoming.push(frame.chunk)
          return
        }
        if (frame.kind === PUT_IN.END) incoming.push(null)
      })

      stream.on('end', () => {
        if (!sawStart) {
          return finish({ ok: false, files: 0, bytes: 0, message: 'put received no START frame' })
        }
        incoming.push(null)
      })
      stream.on('error', (err) => finish({ ok: false, files: 0, bytes: 0, message: err.message }))
    })

    return extraction
  })

  // get: pack a path and stream it out.
  //
  // Same shape note in reverse: for a single REQUEST with a streaming response, the decoded request
  // arrives as `stream.data` -- there is no 'data' event to listen for.
  rpc.onGet(async (stream) => {
    const req = stream.data || {}
    const src = req.path
    const globs = req.globs || []

    try {
      fs.statSync(src)
    } catch {
      stream.write(frames.getError(`no such path in the sandbox: ${src}`))
      return stream.end()
    }

    let match = () => true
    if (globs.length) {
      if (picomatch) {
        const matchers = globs.map((g) => picomatch(g))
        match = (rel) => matchers.some((m) => m(rel))
      } else {
        // No glob engine in this image. Refuse rather than fall back: matching nothing silently
        // loses artifacts (observed -- an `out/**` artifact came back empty and looked like a
        // broken build), and matching everything could return more than was asked for. Neither is
        // an acceptable guess.
        stream.write(
          frames.getError(
            'this sandbox image has no glob engine, so a globbed get cannot be served. Rebuild it: bare scripts/build/agent.js'
          )
        )
        return stream.end()
      }
    }

    // Symlinks are skipped rather than followed, so a build cannot use one to smuggle out anything
    // it could merely read.
    const packer = transfer.pack(src, { match })

    await new Promise((resolve) => {
      packer.on('data', (chunk) => stream.write(frames.getChunk(chunk)))
      packer.on('error', (err) => {
        stream.write(frames.getError(err.message))
        resolve()
      })
      packer.on('end', () => {
        stream.write(frames.getDone(packer.stats))
        resolve()
      })
    })
    stream.end()
  })

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
  COMMANDS,
  strayFds,
  scanFds,
  FD_SCAN_OK,
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
