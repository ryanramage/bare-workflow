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
const os = require('bare-os')
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

test('the fd scan says whether it could run, not just what it found', (t) => {
  // The bug this pins: `strayFds()` caught the procfs read error and returned `[]`, so on a platform
  // without /proc the leak detector reported clean for every process. It passed on macOS while
  // measuring nothing -- and so did the assertion below whose entire job is to catch a leak.
  const scan = agent.scanFds()
  t.ok(typeof scan.status === 'string' && scan.status.length > 0, 'status: ' + scan.status)
  // Not asserted as empty -- see the delta note below. This process is shared with every other test
  // file, and by the time this runs an earlier one has legitimately left descriptors open. (The scan
  // reporting them is the detector working, not failing: test/store.js leaves one on a /tmp drive
  // path, which is a real fd leak in that test.)
  t.ok(Array.isArray(scan.fds), 'reports a list of findings, whatever this process already holds')

  if (scan.status !== agent.FD_SCAN_OK) {
    // Deliberately not a pass dressed up as a skip: state which platform, and that the detector is
    // inert here rather than satisfied.
    t.comment(`fd scanning is unavailable on ${os.platform()}: ${scan.status}`)
    t.comment('the leak assertion below cannot run; it is not being reported as passing')
    return
  }

  // Both halves matter. "Any fd above 2" would fire on the Bare runtime's own dozen descriptors
  // (eventpoll, io_uring, eventfd, pipes) and get ignored; a check that never fires is equally
  // useless. So: clean process reports nothing, and a real host handle is caught.
  //
  // The file only has to exist and be outside the allowed prefixes. It used to be /etc/hostname,
  // which does not exist on macOS -- and because this is a sync test, the ENOENT propagated out of
  // brittle as an unhandled rejection and killed the whole run at test 165 of ~290.
  const host = ['/etc/hostname', '/etc/hosts', '/etc/passwd'].find((f) => fs.existsSync(f))
  t.ok(host, 'found a host file to open: ' + host)

  // Asserted as a DELTA, not against an empty baseline.
  //
  // This test runs inside the shared brittle process as test ~180 of ~290, and by then earlier files
  // have left descriptors open -- test/store.js leaves one on a /tmp drive path, which the darwin
  // scan correctly reports. Asserting "exactly one stray" only held when this file ran alone, so it
  // passed in isolation and failed in the suite. What the detector actually promises is that opening
  // a host handle ADDS a finding, and closing it removes it again.
  //
  // Compared against the RESOLVED path: on macOS `/etc` is a symlink to `/private/etc` and lsof
  // reports what the descriptor points at, so asserting the path we opened would fail on a platform
  // difference rather than on anything being wrong.
  const resolved = fs.realpathSync(host)
  const before = agent.strayFds()
  const fd = fs.openSync(host, 'r')
  try {
    const during = agent.strayFds()
    const added = during.filter((x) => !before.includes(x))
    t.is(added.length, 1, `opening a host file adds exactly one finding: ${added.join(', ')}`)
    t.ok(added[0] && added[0].endsWith(':' + resolved), `named ${resolved}: ` + added[0])
  } finally {
    fs.closeSync(fd)
  }
  t.alike(agent.strayFds(), before, 'and it clears when closed')
})

test("the fd scan does not fire on the runtime's own plumbing", (t) => {
  // The other half of the detector, and the one that decides whether it survives contact with
  // reality. A control that fires on every startup gets switched off, and `lib/sandbox.js` REFUSES a
  // sandbox whose agent reports any stray -- so a false positive here does not just add noise, it
  // makes every run fail to start.
  //
  // This bit for real while writing the darwin backend. Bare holds open pipes, kqueues, unix sockets
  // and directory handles on `/` in every process; lsof names the anonymous ones `->0x<pointer>`,
  // which is the same thing procfs spells `socket:[N]` and `pipe:[N]`. Treating lsof's `unix` type as
  // always-reportable -- the obvious reading, since a named socket IS always a finding -- flagged
  // Bare's own sockets on every single startup.
  const scan = agent.scanFds()
  if (scan.status !== agent.FD_SCAN_OK) {
    t.comment(`fd scanning unavailable here: ${scan.status}`)
    return t.pass('skipped')
  }

  // Not "the list is empty" -- this shares a process with every other test file, so it legitimately
  // is not. The property is narrower and is the one that matters: whatever IS reported, none of it is
  // the runtime's own plumbing.
  const anon = scan.fds.filter((x) => /->0x[0-9a-f]+|count=/.test(x))
  t.alike(anon, [], 'anonymous kernel objects are never reported: ' + JSON.stringify(anon))
  const rootDirs = scan.fds.filter((x) => /^\d+:\/$/.test(x))
  t.alike(rootDirs, [], "Bare's root directory handles are never reported")
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
