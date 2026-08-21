'use strict'

// Job runner: execute one job's steps in one sandbox.
//
// M1 scope on purpose -- one job, steps in order. The DAG scheduler, matrix expansion and
// cross-job outputs come next. What matters is that the seam is already right: a runner takes a
// plain serializable job plus a launcher and emits events, so dispatching that same job to a peer
// later is a transport change rather than a rewrite.
//
// Step semantics kept from wrkflw because they are correct there:
//   * `outcome` is the raw result, `conclusion` is the result after continue-on-error. Collapsing
//     the two loses the ability to say "this step failed but the job carried on".
//   * a failing step sets job status, so later conditionals can see it.

const EventEmitter = require('bare-events')

const { create: createSandbox } = require('../sandbox.js')

class JobRun extends EventEmitter {
  constructor({ job, launcher, env = {}, logBytes, signal }) {
    super()
    this.job = job
    this.launcher = launcher
    this.env = env
    this.logBytes = logBytes
    this.signal = signal
    this.steps = []
    this.status = 'pending'
  }

  async run() {
    const box = createSandbox({
      launcher: this.launcher,
      ...(this.logBytes ? { logBytes: this.logBytes } : {})
    })

    this.status = 'running'
    this.emit('job', { phase: 'start', job: this.job.id })

    try {
      await box.prepare()
      this.emit('sandbox', {
        tier: box.tier,
        agent: box.hello.agent,
        attestation: box.attestation
      })

      for (const step of this.job.steps) {
        const result = await this._runStep(box, step)
        this.steps.push(result)

        // continue-on-error is exactly what separates outcome from conclusion: the step still
        // failed, the job just does not stop for it.
        if (result.conclusion === 'failure') {
          this.status = 'failure'
          break
        }
      }

      if (this.status === 'running') this.status = 'success'
    } catch (err) {
      this.status = 'failure'
      throw err
    } finally {
      await box.dispose()
    }

    this.emit('job', { phase: 'end', job: this.job.id, status: this.status })
    return { job: this.job.id, status: this.status, steps: this.steps }
  }

  async _runStep(box, step) {
    this.emit('step', { phase: 'start', index: step.index, name: step.name, id: step.id })

    const run = box.exec(
      {
        run: step.run,
        shell: step.shell,
        ...(step.cwd ? { cwd: step.cwd } : {}),
        // Precedence: workflow env, then job, then step. Narrowest scope wins.
        env: { ...this.env, ...this.job.env, ...step.env }
      },
      { timeoutMs: step.timeoutMs, signal: this.signal }
    )

    run.stdout.on('data', (chunk) => this.emit('stdout', { index: step.index, chunk }))
    run.stderr.on('data', (chunk) => this.emit('stderr', { index: step.index, chunk }))
    run.on('truncated', (info) => this.emit('truncated', { index: step.index, ...info }))

    const res = await run.wait()

    const outcome = res.code === 0 ? 'success' : res.cancelled ? 'cancelled' : 'failure'
    const conclusion = outcome !== 'success' && step.continueOnError ? 'success' : outcome

    const result = {
      index: step.index,
      id: step.id,
      name: step.name,
      outcome,
      conclusion,
      code: res.code,
      error: res.error,
      timedOut: res.timedOut,
      cancelled: res.cancelled,
      truncated: res.truncated,
      bytesOut: res.bytesOut,
      ms: res.ms
    }

    this.emit('step', { phase: 'end', ...result })
    return result
  }
}

function create(opts) {
  return new JobRun(opts)
}

module.exports = { JobRun, create }
