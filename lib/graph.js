'use strict'

// Task expansion and the ready-queue scheduler.
//
// Two jobs here:
//
//   1. EXPANSION -- a job with N targets becomes N tasks. A task is a plain serializable object, so
//      the same object can later be handed to a remote peer over RPC. `targets` is both a matrix
//      axis and a placement constraint, which is what makes farm routing fall out of the schema
//      rather than being bolted on.
//
//   2. SCHEDULING -- a READY QUEUE, not wrkflw's level-batched Kahn sort. Batching imposes a barrier
//      per level, so a fast job cannot start its dependent while a slow sibling in the same level is
//      still running. Event-driven instead: when a task finishes, decrement its dependents' pending
//      count and start any that reach zero. Same cycle detection, same `--job` filtering, strictly
//      better wall-clock -- and it is the shape the farm needs anyway, because peers finish at
//      wildly different times.
//
// Dependencies are declared between JOBS but scheduled between TASKS: `test` needing `build` means
// every `test` task waits for every `build` task. Per-target dependency (test:linux-x64 waiting only
// on build:linux-x64) is a finer-grained thing to add later; doing it silently now would change what
// `needs` means.

const WorkflowError = require('./errors.js')

// Task ids are deterministic and filesystem/URL safe, because they name containers, log files and
// (later) work items on the wire: `make:linux-x64`, `lint:host`.
function taskId(jobId, target) {
  return `${jobId}:${target}`
}

// Expand a workflow into tasks, in a deterministic order.
function expand(workflow, opts = {}) {
  const only = opts.job || null
  const jobIds = Object.keys(workflow.jobs)

  if (only && !workflow.jobs[only]) {
    throw WorkflowError.SCHEMA_INVALID(
      `no such job ${JSON.stringify(only)}; available: ${jobIds.join(', ')}`
    )
  }

  // `--job x` keeps x AND everything it transitively needs -- running a job without its
  // dependencies would be a different workflow, not a subset of one.
  const keep = only ? transitive(workflow, only) : new Set(jobIds)

  const tasks = []
  for (const jobId of jobIds) {
    if (!keep.has(jobId)) continue
    const job = workflow.jobs[jobId]
    for (const target of job.targets) {
      tasks.push({
        id: taskId(jobId, target),
        job: jobId,
        target,
        // Which task ids must finish first. Job-level `needs`, expanded across targets.
        needs: job.needs
          .filter((n) => keep.has(n))
          .flatMap((n) => workflow.jobs[n].targets.map((t) => taskId(n, t))),
        needsJobs: job.needs.filter((n) => keep.has(n))
      })
    }
  }

  detectCycles(workflow, keep)
  return tasks
}

// Everything `start` transitively needs, including itself.
function transitive(workflow, start) {
  const seen = new Set()
  const stack = [start]
  while (stack.length) {
    const id = stack.pop()
    if (seen.has(id)) continue
    seen.add(id)
    const job = workflow.jobs[id]
    if (!job) continue
    for (const need of job.needs) stack.push(need)
  }
  return seen
}

// Depth-first cycle detection, reporting the cycle as a path so it is actionable. The cycle is
// rotated to start at its lexicographically smallest member, so `a -> b -> a` and `b -> a -> b`
// produce the same message rather than depending on iteration order.
function detectCycles(workflow, keep) {
  const WHITE = 0
  const GREY = 1
  const BLACK = 2
  const colour = new Map()
  for (const id of keep) colour.set(id, WHITE)

  const path = []

  function visit(id) {
    colour.set(id, GREY)
    path.push(id)
    for (const need of workflow.jobs[id].needs) {
      if (!keep.has(need)) continue
      const c = colour.get(need)
      if (c === GREY) {
        const from = path.indexOf(need)
        throw WorkflowError.CYCLE(
          'dependency cycle: ' + normalizeCycle(path.slice(from)).join(' -> ')
        )
      }
      if (c === WHITE) visit(need)
    }
    path.pop()
    colour.set(id, BLACK)
  }

  for (const id of keep) if (colour.get(id) === WHITE) visit(id)
}

function normalizeCycle(cycle) {
  let min = 0
  for (let i = 1; i < cycle.length; i++) if (cycle[i] < cycle[min]) min = i
  const rotated = [...cycle.slice(min), ...cycle.slice(0, min)]
  return [...rotated, rotated[0]]
}

// Run tasks respecting dependencies, up to `concurrency` at a time.
//
// `runTask(task)` returns a result with a `status` of 'success' | 'failure' | 'skipped'.
// `onSkip(task, reason)` is called for tasks that never run.
async function schedule(tasks, runTask, opts = {}) {
  const concurrency = Math.max(1, opts.concurrency || 1)
  const failFast = opts.failFast !== false

  const byId = new Map(tasks.map((t) => [t.id, t]))
  const pending = new Map(tasks.map((t) => [t.id, t.needs.filter((n) => byId.has(n)).length]))
  const dependents = new Map(tasks.map((t) => [t.id, []]))
  for (const task of tasks) {
    for (const need of task.needs) {
      if (byId.has(need)) dependents.get(need).push(task.id)
    }
  }

  const results = new Map()
  const ready = tasks.filter((t) => pending.get(t.id) === 0).map((t) => t.id)
  const running = new Set()
  let failed = false

  // A task whose dependency failed never runs, and says so. Cascading the skip is what stops a
  // dependent from running against half-built inputs.
  function skipDependents(id, reason) {
    for (const dep of dependents.get(id) || []) {
      if (results.has(dep) || running.has(dep)) continue
      results.set(dep, { id: dep, status: 'skipped', reason })
      if (opts.onSkip) opts.onSkip(byId.get(dep), reason)
      skipDependents(dep, reason)
    }
  }

  async function launch(id) {
    running.add(id)
    let result
    try {
      result = await runTask(byId.get(id))
    } catch (err) {
      result = { status: 'failure', error: err.message }
    }
    running.delete(id)
    results.set(id, { id, ...result })

    if (result.status === 'failure') {
      failed = true
      skipDependents(id, `dependency ${id} failed`)
      return
    }

    for (const dep of dependents.get(id) || []) {
      if (results.has(dep)) continue
      const left = pending.get(dep) - 1
      pending.set(dep, left)
      if (left === 0) ready.push(dep)
    }
  }

  const inflight = new Set()
  while (ready.length || inflight.size) {
    while (ready.length && inflight.size < concurrency) {
      if (failed && failFast) break
      const id = ready.shift()
      if (results.has(id)) continue
      const p = launch(id).then(() => inflight.delete(p))
      inflight.add(p)
    }
    if (inflight.size === 0) break
    await Promise.race(inflight)
  }

  // Anything still unstarted was blocked by a failure (or by fail-fast stopping the queue).
  for (const task of tasks) {
    if (!results.has(task.id)) {
      const reason = failed ? 'a previous task failed' : 'not scheduled'
      results.set(task.id, { id: task.id, status: 'skipped', reason })
      if (opts.onSkip) opts.onSkip(task, reason)
    }
  }

  // Return in the original deterministic task order, not completion order.
  return tasks.map((t) => results.get(t.id))
}

module.exports = { expand, schedule, taskId, transitive, detectCycles }
