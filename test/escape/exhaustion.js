'use strict'

// Resource-exhaustion arm of the escape suite.
//
// A sandbox that cannot be escaped but CAN wedge the host is still a broken sandbox: a build farm
// peer that a single job can render unusable is a denial-of-service primitive. These tests are
// deliberately bounded rather than true bombs -- an unbounded fork bomb that escapes its limit
// would take the developer's machine down with it, which is a bad way to learn the limit is
// missing. Each probe attempts a known, finite overshoot and asserts it was refused.
//
// Small limits are injected per test so the overshoot is fast and obvious.

const test = require('brittle')
const os = require('bare-os')
const fs = require('bare-fs')
const h = require('./harness.js')

let ENVP = null

test('exhaustion: environment', async (t) => {
  ENVP = await h.probeEnvironment()
  if (!ENVP.ok) {
    t.comment('skipping: ' + ENVP.why)
    t.pass('skipped')
    return
  }
  t.pass('ready')
})

// A host filesystem whose free-space numbers actually move, so the exhaustion assertion can fail.
//
// Checks that the candidate reports a non-zero total: an autofs trigger like macOS's /home answers
// statfs with all zeroes rather than erroring, which is exactly how this control went vacuous.
function watchable() {
  if (!fs.statfsSync) return null
  for (const p of ['/home', os.homedir ? os.homedir() : null, '/tmp', '/']) {
    if (!p) continue
    try {
      const st = fs.statfsSync(p)
      if (Number(st.blocks) > 0 && Number(st.bsize) > 0) return { path: p, before: st }
    } catch {}
  }
  return null
}

test('workspace writes are capped and cannot fill the host', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')

  // The reason /w is a size-capped tmpfs rather than a podman volume: volumes on overlay have NO
  // size limit, so this exact dd would eat the host's disk. If someone "optimizes" /w back to a
  // volume, this test is what fails.
  //
  // The path used to be a hardcoded '/home'. On macOS that is an autofs trigger (`map auto_home`)
  // reporting ZERO blocks -- verified with both df and statfsSync -- so `delta` was always 0 and the
  // "host free space unchanged" assertion below was true no matter what happened. A disk-exhaustion
  // control that cannot fail is the `ip route` failure mode recorded in CLAUDE.md, and it is worse
  // than no control because it reads as evidence.
  const watch = watchable()

  // dd prints the ENOSPC line BEFORE its two summary lines, so `tail -1` looks at the wrong one.
  // Grep the whole stream instead.
  const script =
    'dd if=/dev/zero of=/w/big bs=1M count=256 2>&1 | grep -ci "no space left"; ' +
    'echo "wrote=$(stat -c %s /w/big 2>/dev/null || echo 0)"'

  const res = await h.runHardened('container', ENVP.digest, script, {
    // Every tmpfs size is set, not just the workspace: they are all RAM-backed and all charged to
    // the same memory cgroup, so overriding one and inheriting the others is how you end up with a
    // 1 GiB /tmp under a 512 MiB memory cap. argv.resolveLimits() now refuses that pairing, which is
    // what makes this spec explicit rather than merely lucky.
    spec: {
      limits: {
        workspaceBytes: 32 * 1024 * 1024,
        tmpBytes: 32 * 1024 * 1024,
        shmBytes: 8 * 1024 * 1024,
        headroomBytes: 64 * 1024 * 1024,
        memoryBytes: 512 * 1024 * 1024
      }
    },
    timeoutMs: 120000
  })

  const wrote = Number((res.stdout.match(/wrote=(\d+)/) || [])[1] || 0)
  t.ok(wrote > 0, 'the workspace is writable at all')
  t.ok(wrote <= 32 * 1024 * 1024, `write capped at the tmpfs size, got ${wrote} bytes`)
  const enospc = Number((res.stdout.match(/^(\d+)$/m) || [])[1] || 0)
  t.ok(enospc > 0, 'dd hit ENOSPC rather than growing forever')

  // Refuse to report a pass we did not earn: if nothing on this host reports real block counts the
  // measurement is impossible, and that is said out loud rather than skipped past.
  t.ok(watch, 'found a host filesystem that reports real block counts')
  if (watch) {
    const after = fs.statfsSync(watch.path)
    // tmpfs is RAM-backed, so this should be trivially true -- assert it anyway to pin the
    // property, because it is the whole point of the choice.
    const delta = Number(watch.before.bfree - after.bfree) * Number(watch.before.bsize)
    t.ok(
      Math.abs(delta) < 64 * 1024 * 1024,
      `host ${watch.path} free space essentially unchanged (delta ${delta})`
    )
  }
})

test('the pid limit reaches the cgroup', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')
  // Asserted in a healthy container, because a pid-starved shell cannot reliably report on
  // itself -- see the storm test below.
  const res = await h.runHardened('container', ENVP.digest, 'cat /sys/fs/cgroup/pids.max', {
    spec: { limits: { pids: 64 } }
  })
  t.is(res.stdout.trim(), '64', 'cgroup pids.max reflects the spec')
})

test('fork storms are contained, and the host survives', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')

  // Learned the hard way: a shell that has exhausted its pid budget dies WITHOUT flushing its
  // pending output -- the first version of this test asked the starved shell to print a count and
  // got an empty stdout and exit 0, which looks identical to "nothing happened". So do not ask the
  // victim for a report. Assert on stderr (bash announces "fork: retry: Resource temporarily
  // unavailable") and on the host being unharmed afterwards.
  const script = 'for i in $(seq 1 400); do sleep 30 & done; wait'

  const res = await h.runHardened('container', ENVP.digest, script, {
    spec: { limits: { pids: 64, nproc: 64, wallClockMs: 20000 } },
    timeoutMs: 120000
  })

  const blob = res.stdout + res.stderr
  t.ok(
    /retry|Resource temporarily unavailable|cannot fork|fork failed/i.test(blob) || res.code !== 0,
    'the storm was refused rather than served: ' +
      (blob.trim().split('\n').slice(0, 2).join(' | ') || `exit ${res.code}`)
  )

  // The real assertion: the host is still healthy. If the limit had not held, this next trivial
  // container could not start.
  const after = await h.runHardened('container', ENVP.digest, 'echo host-ok', { timeoutMs: 60000 })
  t.is(after.stdout.trim(), 'host-ok', 'host can still start containers after the storm')
})

test('a wall-clock overrun is killed', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')

  const started = Date.now()
  const res = await h.runHardened('container', ENVP.digest, 'sleep 120; echo SHOULD-NOT-PRINT', {
    spec: { limits: { wallClockMs: 5000 } },
    timeoutMs: 90000
  })
  const elapsed = Date.now() - started

  t.absent(res.stdout.includes('SHOULD-NOT-PRINT'), 'the step did not run to completion')
  // podman --timeout is level 3 of the cancellation ladder; the driver's own timer is level 2 and
  // does not exist yet, so this is podman enforcing it unaided.
  t.ok(elapsed < 60000, `killed well before the harness timeout (${elapsed}ms)`)
  t.not(res.code, 0, 'non-zero exit on timeout')
})

test('log floods do not have to be buffered by the runner', async (t) => {
  if (!ENVP || !ENVP.ok) return t.pass('skipped')

  // We have no logBytes cap in the driver yet -- that lands with the agent. What this test pins
  // today is that a large output stream is delivered incrementally and correctly rather than
  // wedging, so the cap has somewhere to hook in later.
  let chunks = 0
  let bytes = 0
  const script = 'for i in $(seq 1 20000); do echo "line-$i-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; done'
  const res = await h.runHardened('container', ENVP.digest, script, { timeoutMs: 120000 })
  bytes = res.stdout.length
  chunks = res.stdout.split('\n').length

  t.is(res.code, 0)
  t.ok(chunks > 19000, `all lines delivered (${chunks})`)
  t.ok(bytes > 500000, `substantial volume moved (${bytes} bytes)`)
  t.ok(res.stdout.includes('line-20000-'), 'stream not truncated mid-flight')
})
