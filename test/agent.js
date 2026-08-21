'use strict'

// Agent-specific unit tests.
//
// The Sandbox LIFECYCLE (handshake, exec, streaming, timeouts, cancellation, log caps, dispose) is
// no longer tested here -- it moved to test/support/lifecycle.js, which test/lifecycle.js runs
// against every launcher on the machine, including a real krun microVM. Duplicating those
// assertions against one launcher would just be a slower copy.
//
// What stays: pure functions inside the agent, and the driver-side gates that need a stub rather
// than a real sandbox.

const test = require('brittle')
const fs = require('bare-fs')
const { create: sandbox, onAbort } = require('../lib/sandbox.js')
const { LocalLauncher } = require('./support/local-launcher.js')
const agent = require('../lib/agent/index.js')

test('resolveShell finds a shell without an inherited PATH', (t) => {
  // The no-inherited-environment rule means a step may arrive with no PATH at all, so the agent
  // cannot rely on the OS resolving `bash` for it.
  t.is(agent.resolveShell('/bin/sh', {}), '/bin/sh', 'an explicit path is used as given')

  const resolved = agent.resolveShell('sh', {})
  t.ok(resolved.startsWith('/') && resolved.endsWith('/sh'), 'resolved absolutely: ' + resolved)

  t.is(
    agent.resolveShell('definitely-not-a-shell', {}),
    'definitely-not-a-shell',
    'unresolvable names pass through so spawn reports a real errno'
  )

  // A PATH sent by the driver is honoured ahead of the built-in dirs.
  t.is(
    agent.resolveShell('sh', { PATH: '/nonexistent' }),
    '/bin/sh',
    'falls back past a bad PATH entry'
  )
})

test('strayFds ignores runtime plumbing but catches a real leak', (t) => {
  // Both halves matter. "Any fd above 2" would fire on the Bare runtime's own dozen descriptors
  // (eventpoll, io_uring, eventfd, pipes) and get ignored; a check that never fires is equally
  // useless. So: clean process reports nothing, and a real host handle is caught.
  t.alike(agent.strayFds(), [], 'clean process reports nothing')

  const fd = fs.openSync('/etc/hostname', 'r')
  try {
    const stray = agent.strayFds()
    t.is(stray.length, 1, 'an inherited host-file handle is caught')
    t.ok(stray[0].endsWith(':/etc/hostname'), 'and named: ' + stray[0])
  } finally {
    fs.closeSync(fd)
  }
  t.alike(agent.strayFds(), [], 'and it clears when closed')
})

test('ensureWorkspace creates the subtree it is given', (t) => {
  // The workspace tmpfs arrives empty on every start regardless of what the image built, so the
  // agent has to create /w/{src,home,artifacts} itself -- there is no shared mount to do it from
  // outside.
  const root = '/tmp/bw-ensure-' + Date.now()
  const made = agent.ensureWorkspace(root)
  t.ok(made.length >= 4, 'created the root and its subdirs')
  for (const dir of ['', '/src', '/home', '/artifacts']) {
    t.ok(fs.statSync(root + dir).isDirectory(), `${root + dir} exists`)
  }
  t.execution(() => agent.ensureWorkspace(root), 'idempotent')
  fs.rmSync(root, { recursive: true, force: true })
})

test('onAbort accepts both signal shapes', (t) => {
  // Bare has no AbortController/AbortSignal/EventTarget at all, so requiring a web signal would
  // force a dependency on every caller and requiring an emitter would break Node callers.
  const EventEmitter = require('bare-events')
  let fired = 0

  const emitter = new EventEmitter()
  onAbort(emitter, () => fired++)
  emitter.emit('abort')
  t.is(fired, 1, 'EventEmitter shape')

  let handler = null
  const webish = {
    aborted: false,
    addEventListener: (name, fn) => {
      handler = fn
    }
  }
  onAbort(webish, () => fired++)
  handler()
  t.is(fired, 2, 'AbortSignal shape')

  onAbort({ aborted: true }, () => fired++)
  t.is(fired, 3, 'an already-aborted signal fires immediately')

  t.exception(() => onAbort({}, () => {}), /INVALID_SPEC/, 'anything else is rejected loudly')
})

test('exec before prepare, and after dispose, both throw', async (t) => {
  const box = sandbox({ launcher: new LocalLauncher() })
  t.exception(() => box.exec({ run: 'true' }), /call prepare/)
  await box.prepare()
  await box.dispose()
  t.exception(() => box.exec({ run: 'true' }), /disposed/)
})

test('prepare refuses a sandbox with leaked descriptors', async (t) => {
  // A handle onto a host path -- or any named socket -- means something leaked in. Refuse the job
  // rather than run a workload beside an inherited handle. Driven with a stub agent, because the
  // real one (correctly) never reports one.
  const stub = {
    tier: 'stub',
    async spawn() {
      const { duplexPair } = require('bare-stream')
      const protocol = require('../lib/protocol.js')
      const [ours, theirs] = duplexPair()
      const server = protocol.createRPC(theirs)
      server.onHello(() => ({
        agent: 'stub',
        platform: 'linux',
        arch: 'x64',
        pid: 1,
        strayFds: ['9:/run/user/1000/podman/podman.sock'],
        cwd: '/w'
      }))
      return { stream: ours, close: async () => {} }
    }
  }
  const box = sandbox({ launcher: stub })
  await t.exception(box.prepare(), /ISOLATION_UNAVAILABLE/, 'a leaked socket aborts the job')
})

test('allowStrayFds is an explicit opt-out, not a default', async (t) => {
  const stub = {
    tier: 'stub',
    async spawn() {
      const { duplexPair } = require('bare-stream')
      const protocol = require('../lib/protocol.js')
      const [ours, theirs] = duplexPair()
      const server = protocol.createRPC(theirs)
      server.onHello(() => ({
        agent: 'stub',
        platform: 'linux',
        arch: 'x64',
        pid: 1,
        strayFds: ['9:/etc/shadow'],
        cwd: '/w'
      }))
      server.onPing((req) => ({ nonce: req.nonce }))
      return { stream: ours, close: async () => {} }
    }
  }
  const box = sandbox({ launcher: stub, allowStrayFds: true })
  await t.execution(box.prepare(), 'opting in lets a leak through -- deliberately loud in the API')
  t.alike(box.hello.strayFds, ['9:/etc/shadow'], 'and the leak is still recorded')
  await box.dispose()
})
