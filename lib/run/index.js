'use strict'

// Task runner: execute one task (a job at one target) in one sandbox.
//
// A TASK, not a job: a job with three targets is three tasks, each with its own sandbox. That is
// what makes the unit of work the same shape as the unit of dispatch -- handing a task to a remote
// peer later is a transport change, not a rewrite.
//
// Step semantics kept from wrkflw because they are correct there:
//   * `outcome` is the raw result, `conclusion` is the result after continue-on-error. Collapsing
//     them loses the ability to say "this step failed but the job carried on".
//   * a failing step marks the run failed, which is what `success()` / `failure()` conditions read.
//
// Outputs travel by FILE, never by scraping stdout. GHA's `::set-output::` reads the log, so
// ordinary build output can forge an output -- indefensible in a farm where log lines are
// attacker-controlled by construction.

const EventEmitter = require('bare-events')

const { create: createSandbox } = require('../sandbox.js')
const { interpolate, evaluate } = require('../interpolate.js')
const WorkflowError = require('../errors.js')
const targetsLib = require('../targets.js')

class TaskRun extends EventEmitter {
  constructor({
    task,
    job,
    launcher,
    env = {},
    needs = {},
    run = {},
    store,
    workdir,
    logBytes,
    signal
  }) {
    super()
    this.task = task
    this.job = job
    this.launcher = launcher
    this.env = env
    this.needs = needs // { [jobId]: { outputs, status } } for declared needs only
    this.runMeta = run
    // Optional: without a store, artifacts are simply not moved. Declaring them and then silently
    // dropping them would be worse than not supporting them.
    this.store = store || null
    this.workdir = workdir || '/w/src'
    this.logBytes = logBytes
    this.signal = signal

    this.steps = []
    this.stepOutputs = {} // { [stepId]: { outputs, status } }
    this.outputs = {}
    this.artifacts = []
    this.status = 'pending'
    this.failed = false
  }

  // The scope visible to `{{ }}` and `if:`. A closed set of roots -- there is no path from a
  // workflow to arbitrary runner state.
  scope() {
    return {
      target: targetsLib.parse(this.task.target),
      matrix: {}, // free-form matrix axes are not implemented yet; the root exists so a reference
      // to it fails with "unknown reference matrix.x" rather than "unknown root".
      env: { ...this.env, ...this.job.env },
      needs: this.needs,
      steps: this.stepOutputs,
      job: { name: this.job.name, id: this.job.id },
      run: this.runMeta
    }
  }

  async execute() {
    const box = createSandbox({
      launcher: this.launcher,
      ...(this.logBytes ? { logBytes: this.logBytes } : {})
    })

    this.status = 'running'
    this.emit('task', {
      phase: 'start',
      task: this.task.id,
      job: this.job.id,
      target: this.task.target
    })

    try {
      await box.prepare()
      this.emit('sandbox', { tier: box.tier, agent: box.hello.agent, attestation: box.attestation })

      // Source, then prefetched dependencies, then artifacts -- everything a task declared is in
      // place before its first step runs, so a step never has to guess whether its inputs arrived.
      await this._putSource(box)
      await this._putCache(box)
      await this._fetchInputs(box)

      for (const step of this.job.steps) {
        const result = await this._runStep(box, step)
        this.steps.push(result)
        if (result.conclusion === 'failure') {
          this.failed = true
          break
        }
      }

      this.status = this.failed ? 'failure' : 'success'
      // Declared job outputs are resolved after the steps, in the final scope -- so they can refer
      // to any step's outputs regardless of declaration order.
      if (this.status === 'success') {
        this.outputs = this._resolveOutputs()
        // Only collect artifacts from a task that succeeded: publishing the output of a failed build
        // is how a broken binary ends up downstream.
        this.artifacts = await this._collectOutputs(box)
      }
    } catch (err) {
      this.status = 'failure'
      throw err
    } finally {
      await box.dispose()
    }

    this.emit('task', {
      phase: 'end',
      task: this.task.id,
      status: this.status,
      outputs: this.outputs
    })
    return {
      id: this.task.id,
      job: this.job.id,
      target: this.task.target,
      status: this.status,
      steps: this.steps,
      outputs: this.outputs
    }
  }

  // Stream the project directory in.
  //
  // A copy rather than a mount, like everything else crossing this boundary. `.git` and
  // `node_modules` are excluded: the first is large and never needed by a build step, the second is
  // what the prefetched cache exists to reconstruct reproducibly.
  async _putSource(box) {
    if (!this.job.source) return
    const path = require('bare-path')
    const fs = require('bare-fs')
    const abs = path.resolve(this.runMeta.baseDir || '.', this.job.source)
    try {
      if (!fs.statSync(abs).isDirectory()) throw new Error('not a directory')
    } catch {
      throw WorkflowError.SCHEMA_INVALID(`source directory does not exist: ${abs}`)
    }

    const skip = new Set(['.git', 'node_modules', '.bw-state', 'out'])
    const put = await box.put(abs, this.workdir, {
      match: (rel) => !rel.split('/').some((part) => skip.has(part))
    })
    this.emit('source', { from: abs, to: this.workdir, files: put.files, bytes: put.bytes })
  }

  // Hand in whatever the host prefetched, read-only as far as the build is concerned.
  async _putCache(box) {
    if (!this.job.prefetch || this.job.prefetch.length === 0) return
    if (!this.runMeta.cacheDir) {
      throw WorkflowError.PREFETCH_INVALID(
        `jobs.${this.job.id} declares prefetch but the runner supplied no cache directory`
      )
    }
    const fs = require('bare-fs')
    try {
      fs.statSync(this.runMeta.cacheDir)
    } catch {
      // Nothing was fetched (an empty lockfile, say). Not an error -- the install step will simply
      // find an empty cache and fail on its own terms if it actually needed something.
      return
    }
    const put = await box.put(this.runMeta.cacheDir, '/w/cache')
    this.emit('cache', { to: '/w/cache', files: put.files, bytes: put.bytes })
  }

  // Materialize declared input artifacts and stream them into the sandbox.
  async _fetchInputs(box) {
    const inputs = this.job.artifacts && this.job.artifacts.in
    if (!inputs || inputs.length === 0) return
    if (!this.store) {
      throw WorkflowError.ARTIFACT_MISSING(
        `jobs.${this.job.id} declares input artifacts but this run has no artifact store`
      )
    }

    const fs = require('bare-fs')
    const path = require('bare-path')

    for (const input of inputs) {
      const name = interpolate(input.name, this.scope())
      const staging = path.join(
        this.runMeta.state || '/tmp',
        'artifacts-in',
        `${this.task.id.replace(/[^A-Za-z0-9._-]/g, '-')}-${name}`
      )
      try {
        fs.rmSync(staging, { recursive: true, force: true })
      } catch {}

      const got = await this.store.get(name, staging)
      const dest = path.posix.join(this.workdir, input.to === '.' ? '' : input.to)
      const put = await box.put(staging, dest)
      this.emit('artifact', { phase: 'in', name, files: put.files, bytes: put.bytes, to: dest })

      try {
        fs.rmSync(staging, { recursive: true, force: true })
      } catch {}
      void got
    }
  }

  // Stream declared output artifacts out of the sandbox and into the store.
  async _collectOutputs(box) {
    const outs = this.job.artifacts && this.job.artifacts.out
    if (!outs || outs.length === 0) return []
    if (!this.store) {
      throw WorkflowError.ARTIFACT_MISSING(
        `jobs.${this.job.id} declares output artifacts but this run has no artifact store`
      )
    }

    const fs = require('bare-fs')
    const path = require('bare-path')
    const collected = []

    for (const out of outs) {
      const scope = this.scope()
      // The name is interpolated so a fan-out job can produce one artifact per target
      // (`app-{{ target }}`) rather than four tasks fighting over one name.
      const name = interpolate(out.name, scope)
      const pattern = interpolate(out.path, scope)

      // Split a glob into the deepest fixed prefix (what to fetch) and the pattern (what to keep).
      const parts = pattern.split('/')
      const fixed = []
      while (parts.length && !/[*?[\]]/.test(parts[0])) fixed.push(parts.shift())
      const base = path.posix.join(this.workdir, ...fixed)
      const globs = parts.length ? [parts.join('/')] : []

      const staging = path.join(
        this.runMeta.state || '/tmp',
        'artifacts-out',
        `${this.task.id.replace(/[^A-Za-z0-9._-]/g, '-')}-${name}`
      )
      try {
        fs.rmSync(staging, { recursive: true, force: true })
      } catch {}

      let got
      try {
        got = await box.get(base, staging, { globs })
      } catch (err) {
        if (out.ifNoFilesFound === 'error') throw err
        if (out.ifNoFilesFound === 'warn') {
          this.emit('warning', { message: `artifact ${name}: ${err.message}` })
        }
        continue
      }

      if (got.files === 0) {
        const message = `artifact ${JSON.stringify(name)} matched no files at ${pattern}`
        if (out.ifNoFilesFound === 'error') throw WorkflowError.ARTIFACT_EMPTY(message)
        if (out.ifNoFilesFound === 'warn') this.emit('warning', { message })
        continue
      }

      const stored = await this.store.put(name, staging, { ifNoFilesFound: out.ifNoFilesFound })
      collected.push(stored)
      this.emit('artifact', {
        phase: 'out',
        name,
        files: stored.files,
        bytes: stored.bytes,
        path: pattern
      })

      try {
        fs.rmSync(staging, { recursive: true, force: true })
      } catch {}
    }
    return collected
  }

  _resolveOutputs() {
    const scope = this.scope()
    const out = {}
    for (const key of Object.keys(this.job.outputs)) {
      try {
        out[key] = interpolate(this.job.outputs[key], scope)
      } catch (err) {
        // A declared output that cannot be resolved is a workflow bug, and reporting it beats
        // shipping an empty string that breaks a downstream job in a confusing way.
        throw WorkflowError.EXPR_UNKNOWN_REFERENCE(
          `jobs.${this.job.id}.outputs.${key}: ${err.message.replace(/^[A-Z_]+: /, '')}`
        )
      }
    }
    return out
  }

  async _runStep(box, step) {
    const scope = this.scope()
    const status = { failed: this.failed, cancelled: false }

    // `if:` is EVALUATED, not merely parsed. Carrying a condition without honouring it would be the
    // exact GHA failure mode this project exists to avoid: the workflow says one thing and the
    // runner does another, silently.
    let should = true
    try {
      should = evaluate(step.if, scope, status)
    } catch (err) {
      const result = this._result(step, {
        code: -1,
        error: err.message,
        outcome: 'failure',
        conclusion: 'failure'
      })
      this.steps.push(result)
      this.failed = true
      this.emit('step', { phase: 'end', ...result })
      return result
    }

    if (!should) {
      const result = this._result(step, { code: 0, outcome: 'skipped', conclusion: 'skipped' })
      this.emit('step', { phase: 'end', ...result })
      return result
    }

    // Interpolate the parts of a step that may reference the scope. Deliberately NOT the shell or
    // the timeout: what a step is allowed to do must be knowable before it runs.
    let run
    let cwd
    let env
    let name
    try {
      run = interpolate(step.run, scope)
      cwd = step.cwd ? interpolate(step.cwd, scope) : null
      name = interpolate(step.name, scope)
      env = {}
      for (const key of Object.keys(step.env)) env[key] = interpolate(step.env[key], scope)
    } catch (err) {
      const result = this._result(step, {
        code: -1,
        error: err.message,
        outcome: 'failure',
        conclusion: 'failure'
      })
      this.failed = true
      this.emit('step', { phase: 'end', ...result })
      return result
    }

    this.emit('step', { phase: 'start', index: step.index, name, id: step.id })

    const exec = box.exec(
      {
        run,
        shell: step.shell,
        ...(cwd ? { cwd } : {}),
        env: { ...this.env, ...this.job.env, ...env }
      },
      { timeoutMs: step.timeoutMs, signal: this.signal }
    )

    exec.stdout.on('data', (chunk) => this.emit('stdout', { index: step.index, chunk }))
    exec.stderr.on('data', (chunk) => this.emit('stderr', { index: step.index, chunk }))
    exec.on('truncated', (info) => this.emit('truncated', { index: step.index, ...info }))

    const res = await exec.wait()

    const outcome = res.code === 0 ? 'success' : res.cancelled ? 'cancelled' : 'failure'
    const conclusion = outcome !== 'success' && step.continueOnError ? 'success' : outcome

    // Malformed output lines are surfaced, not swallowed: a dropped output becomes an empty string
    // in a later job, which is exactly the class of mystery failure we are trying to remove.
    if (res.outputErrors && res.outputErrors.length) {
      this.emit('warning', {
        index: step.index,
        message: `malformed step output: ${res.outputErrors.join('; ')}`
      })
    }
    if (res.outputsTruncated) {
      this.emit('warning', {
        index: step.index,
        message: 'step output file exceeded its size cap and was truncated'
      })
    }

    if (step.id) {
      this.stepOutputs[step.id] = { outputs: res.outputs || {}, status: conclusion }
    }

    const result = this._result(step, {
      name,
      code: res.code,
      error: res.error,
      outcome,
      conclusion,
      timedOut: res.timedOut,
      cancelled: res.cancelled,
      truncated: res.truncated,
      bytesOut: res.bytesOut,
      ms: res.ms,
      outputs: res.outputs || {}
    })
    this.emit('step', { phase: 'end', ...result })
    return result
  }

  _result(step, extra) {
    return {
      index: step.index,
      id: step.id,
      name: extra.name || step.name,
      outcome: 'success',
      conclusion: 'success',
      code: 0,
      error: null,
      timedOut: false,
      cancelled: false,
      truncated: false,
      bytesOut: 0,
      ms: 0,
      outputs: {},
      ...extra
    }
  }
}

function create(opts) {
  return new TaskRun(opts)
}

module.exports = { TaskRun, create }
