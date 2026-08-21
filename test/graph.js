'use strict'

// Graph tests: task expansion and the ready-queue scheduler. Pure -- the "runTask" is a stub, so
// these run in milliseconds and cover the scheduling semantics rather than the sandbox.

const test = require('brittle')
const { parse } = require('../lib/schema')
const { expand, schedule, taskId, transitive } = require('../lib/graph.js')

const wf = (src) => parse(src, { filename: 'w.yml' })
const ids = (tasks) => tasks.map((t) => t.id)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

test('a job expands to one task per target', (t) => {
  const w = wf(
    'version: 1\njobs:\n  build:\n    targets: [linux-x64, darwin-arm64]\n    steps: [x]\n'
  )
  t.alike(ids(expand(w)), ['build:linux-x64', 'build:darwin-arm64'], 'declaration order preserved')
})

test('task ids are deterministic and safe to use as names', (t) => {
  // They become container names, log filenames and (later) work items on the wire.
  t.is(taskId('build', 'linux-x64'), 'build:linux-x64')
  const w = wf('version: 1\ntargets: [host]\njobs:\n  a:\n    steps: [x]\n')
  t.alike(ids(expand(w)), ids(expand(w)), 'expansion is stable across calls')
})

test('needs is expanded across every target of the dependency', (t) => {
  // Job-level dependency means ALL of build must finish before ANY of pack starts. Per-target
  // dependency is a finer thing to add later; doing it implicitly would change what needs means.
  const w = wf(
    'version: 1\njobs:\n  build:\n    targets: [linux-x64, linux-arm64]\n    steps: [x]\n  pack:\n    needs: build\n    targets: [host]\n    steps: [x]\n'
  )
  const pack = expand(w).find((x) => x.job === 'pack')
  t.alike(pack.needs, ['build:linux-x64', 'build:linux-arm64'])
  t.alike(pack.needsJobs, ['build'])
})

test('--job keeps the target and its transitive dependencies', (t) => {
  const w = wf(
    'version: 1\ntargets: [host]\njobs:\n  lint:\n    steps: [x]\n  build:\n    needs: lint\n    steps: [x]\n  deploy:\n    needs: build\n    steps: [x]\n  other:\n    steps: [x]\n'
  )
  // Running a job without its dependencies would be a different workflow, not a subset of one.
  t.alike(ids(expand(w, { job: 'build' })), ['lint:host', 'build:host'])
  t.alike(ids(expand(w, { job: 'lint' })), ['lint:host'])
  t.alike([...transitive(w, 'deploy')].sort(), ['build', 'deploy', 'lint'])
  t.exception(() => expand(w, { job: 'nope' }), /no such job/)
})

test('cycles are reported as a path, normalized so the message is stable', (t) => {
  const two =
    'version: 1\njobs:\n  a:\n    needs: b\n    steps: [x]\n  b:\n    needs: a\n    steps: [x]\n'
  const three =
    'version: 1\njobs:\n  a:\n    needs: c\n    steps: [x]\n  b:\n    needs: a\n    steps: [x]\n  c:\n    needs: b\n    steps: [x]\n'
  t.exception(() => expand(wf(two)), /dependency cycle: a -> b -> a/)
  t.exception(() => expand(wf(three)), /dependency cycle: a -> c -> b -> a/)
})

// --- scheduling ------------------------------------------------------------------------

test('dependencies are respected', async (t) => {
  const w = wf(
    'version: 1\ntargets: [host]\njobs:\n  a:\n    steps: [x]\n  b:\n    needs: a\n    steps: [x]\n  c:\n    needs: b\n    steps: [x]\n'
  )
  const order = []
  const results = await schedule(
    expand(w),
    async (task) => {
      order.push(task.id)
      return { status: 'success' }
    },
    { concurrency: 4 }
  )
  t.alike(order, ['a:host', 'b:host', 'c:host'])
  t.ok(results.every((r) => r.status === 'success'))
})

test('a ready queue does not make a fast chain wait for a slow sibling', async (t) => {
  // The reason this is not wrkflw's level-batched Kahn sort. Batching puts a barrier between levels,
  // so fast-b would sit behind slow-a for no reason. With peers finishing at wildly different
  // times, that barrier is exactly the wrong shape for a farm.
  const w = wf(
    'version: 1\ntargets: [host]\njobs:\n  slow-a:\n    steps: [x]\n  fast-a:\n    steps: [x]\n  fast-b:\n    needs: fast-a\n    steps: [x]\n'
  )
  const log = []
  await schedule(
    expand(w),
    async (task) => {
      log.push('start ' + task.id)
      await sleep(task.job === 'slow-a' ? 200 : 10)
      log.push('end ' + task.id)
      return { status: 'success' }
    },
    { concurrency: 4 }
  )

  t.ok(
    log.indexOf('start fast-b:host') < log.indexOf('end slow-a:host'),
    'fast-b started while slow-a was still running\n    ' + log.join(' | ')
  )
})

test('concurrency is capped', async (t) => {
  const w = wf(
    'version: 1\ntargets: [linux-x64, linux-arm64, darwin-arm64, win32-x64]\njobs:\n  build:\n    steps: [x]\n'
  )
  let inflight = 0
  let peak = 0
  await schedule(
    expand(w),
    async () => {
      peak = Math.max(peak, ++inflight)
      await sleep(20)
      inflight--
      return { status: 'success' }
    },
    { concurrency: 2 }
  )
  t.is(peak, 2, 'never exceeded the cap')
})

test('concurrency 1 serializes independent tasks', async (t) => {
  const w = wf('version: 1\ntargets: [linux-x64, linux-arm64]\njobs:\n  build:\n    steps: [x]\n')
  let inflight = 0
  let peak = 0
  await schedule(
    expand(w),
    async () => {
      peak = Math.max(peak, ++inflight)
      await sleep(10)
      inflight--
      return { status: 'success' }
    },
    { concurrency: 1 }
  )
  t.is(peak, 1)
})

test('a failure cascades to dependents and spares unrelated tasks', async (t) => {
  const w = wf(
    'version: 1\ntargets: [host]\njobs:\n  a:\n    steps: [x]\n  b:\n    needs: a\n    steps: [x]\n  c:\n    needs: b\n    steps: [x]\n  unrelated:\n    steps: [x]\n'
  )
  const skipped = []
  const results = await schedule(
    expand(w),
    async (task) => ({ status: task.job === 'a' ? 'failure' : 'success' }),
    {
      concurrency: 4,
      failFast: false,
      onSkip: (task, reason) => skipped.push({ id: task.id, reason })
    }
  )

  const byId = new Map(results.map((r) => [r.id, r]))
  t.is(byId.get('a:host').status, 'failure')
  t.is(byId.get('b:host').status, 'skipped', 'the direct dependent is skipped')
  t.is(byId.get('c:host').status, 'skipped', 'and the skip cascades transitively')
  t.is(byId.get('unrelated:host').status, 'success', 'an unrelated task still runs')
  t.ok(
    skipped.some((s) => /dependency a:host failed/.test(s.reason)),
    'the reason names the cause'
  )
})

test('a thrown runTask becomes a failure, not an unhandled rejection', async (t) => {
  const w = wf(
    'version: 1\ntargets: [host]\njobs:\n  a:\n    steps: [x]\n  b:\n    needs: a\n    steps: [x]\n'
  )
  const results = await schedule(
    expand(w),
    async (task) => {
      if (task.job === 'a') throw new Error('sandbox exploded')
      return { status: 'success' }
    },
    { concurrency: 2 }
  )
  t.is(results[0].status, 'failure')
  t.ok(/sandbox exploded/.test(results[0].error))
  t.is(results[1].status, 'skipped')
})

test('results come back in task order, not completion order', async (t) => {
  const w = wf(
    'version: 1\ntargets: [linux-x64, linux-arm64, darwin-arm64]\njobs:\n  build:\n    steps: [x]\n'
  )
  const tasks = expand(w)
  const results = await schedule(
    tasks,
    async (task) => {
      // Finish in reverse, so completion order differs from declaration order.
      await sleep(task.target === 'linux-x64' ? 60 : task.target === 'linux-arm64' ? 30 : 5)
      return { status: 'success' }
    },
    { concurrency: 3 }
  )
  t.alike(
    results.map((r) => r.id),
    ids(tasks),
    'deterministic output ordering'
  )
})

test('an empty task list is not an error', async (t) => {
  const results = await schedule([], async () => ({ status: 'success' }), { concurrency: 2 })
  t.alike(results, [])
})
