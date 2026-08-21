'use strict'

// The bare-workflow CLI.
//
// Two commands at this milestone: `validate` (parse and report) and `run` (parse, pick the
// strongest available isolation tier, and execute one job's steps inside it). Everything the CLI
// does is a thin composition of lib/ -- deliberately, so the same operations are usable as a
// library and later over RPC from a farm peer.

const fs = require('bare-fs')
const path = require('bare-path')
const env = require('bare-env')
const { command, flag, arg, summary, description, header, footer } = require('paparam')

const schema = require('./lib/schema')
const targets = require('./lib/targets.js')
const detect = require('./lib/isolation/detect.js')
const { create: createLauncher } = require('./lib/isolation/podman/launcher.js')
const { create: createJobRun } = require('./lib/run')

const DEFAULT_IMAGE = 'localhost/bare-workflow-base:dev'
const SECCOMP = path.resolve(__dirname, 'etc/seccomp/build-v1.json')

// --- output ----------------------------------------------------------------------------
// Structured events in, rendered text out. The renderer is the only thing that knows about
// terminals, so a TUI or a remote log stream can consume the same events later.

const SYM = { ok: '✔', fail: '✖', run: '◉', skip: '⊘', warn: '⚠' }

function write(s) {
  try {
    Bare.stdout.write(s)
  } catch {
    fs.writeSync(1, s)
  }
}

function line(s = '') {
  write(s + '\n')
}

function ms(n) {
  return n < 1000 ? `${n}ms` : `${(n / 1000).toFixed(1)}s`
}

// --- helpers ---------------------------------------------------------------------------

function readWorkflow(file) {
  const resolved = path.resolve(file)
  let source
  try {
    source = fs.readFileSync(resolved, 'utf8')
  } catch {
    fail(`cannot read ${file}`)
  }
  return { workflow: schema.parse(source, { filename: file }), source, resolved }
}

function fail(message, code = 1) {
  try {
    Bare.stderr.write(message + '\n')
  } catch {
    fs.writeSync(2, message + '\n')
  }
  Bare.exitCode = code
  return null
}

function jobsOf(workflow, only) {
  const ids = Object.keys(workflow.jobs)
  if (!only) return ids
  if (!workflow.jobs[only]) {
    fail(`no such job ${JSON.stringify(only)}; available: ${ids.join(', ')}`, 2)
    return null
  }
  return [only]
}

function resolveDigest(image) {
  const { spawnSync } = require('bare-subprocess')
  const r = spawnSync('podman', ['image', 'inspect', image, '--format', '{{.Digest}}'], {
    env: { PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR }
  })
  if (r.status !== 0) return null
  return (r.stdout ? r.stdout.toString() : '').trim() || null
}

// --- validate --------------------------------------------------------------------------

const validate = command(
  'validate',
  summary('Check a workflow file without running it'),
  description(
    'Parses and validates the workflow, reporting the first problem with its path and line.'
  ),
  arg('<file>', 'workflow file'),
  flag('--json', 'machine-readable output'),
  () => {
    const { file } = validate.args
    let parsed
    try {
      parsed = readWorkflow(file)
    } catch (err) {
      if (validate.flags.json) {
        line(JSON.stringify({ ok: false, code: err.code, error: err.message }))
      } else fail(`${SYM.fail} ${err.message}`)
      Bare.exitCode = 1
      return
    }
    if (!parsed) return

    const { workflow } = parsed
    const caps = targets.describe()

    if (validate.flags.json) {
      line(JSON.stringify({ ok: true, workflow }))
      return
    }

    line(`${SYM.ok} ${file} is valid`)
    if (workflow.name) line(`  name     ${workflow.name}`)
    line(`  targets  ${workflow.targets.join(', ')}`)
    for (const id of Object.keys(workflow.jobs)) {
      const job = workflow.jobs[id]
      const missing = targets.unsatisfied(caps, job.targets)
      const note = missing.length ? `  ${SYM.warn} not buildable here: ${missing.join(', ')}` : ''
      line(
        `  job ${id}  ${job.steps.length} step${job.steps.length === 1 ? '' : 's'}, targets ${job.targets.join(', ')}${note}`
      )
    }
  }
)

// --- run -------------------------------------------------------------------------------

const run = command(
  'run',
  summary('Run a workflow in an isolated sandbox'),
  description(
    'Picks the strongest available isolation tier and runs the workflow inside it.\n' +
      'Refuses to run rather than silently dropping to a weaker tier.'
  ),
  arg('<file>', 'workflow file'),
  flag('--job <name>', 'run only this job'),
  flag('--tier <name>', 'minimum isolation tier: microvm (default) or container'),
  flag('--image <ref>', `sandbox image (default ${DEFAULT_IMAGE})`),
  flag('--env <pair>', 'extra KEY=VALUE for every step').multiple(),
  flag('--json', 'newline-delimited JSON events instead of human output'),
  async () => {
    const { file } = run.args
    const flags = run.flags
    const asJson = !!flags.json
    const emit = (event) => {
      if (asJson) line(JSON.stringify(event))
    }

    let parsed
    try {
      parsed = readWorkflow(file)
    } catch (err) {
      if (asJson) {
        line(JSON.stringify({ cmd: 'error', code: err.code, error: err.message }))
      } else {
        fail(`${SYM.fail} ${err.message}`)
      }
      Bare.exitCode = 1
      return
    }
    if (!parsed) return

    const { workflow } = parsed
    const image = flags.image || DEFAULT_IMAGE

    // Pick the tier BEFORE doing anything else, so a machine that cannot isolate never gets as far
    // as looking like it is about to run something.
    let resolved
    try {
      resolved = detect.resolve({ min: flags.tier || 'microvm', image })
    } catch (err) {
      if (asJson) {
        line(JSON.stringify({ cmd: 'error', code: err.code, error: err.message }))
      } else {
        fail(`${SYM.fail} ${err.message}`)
      }
      Bare.exitCode = 78 // EX_CONFIG: the host is not configured to run this safely
      return
    }

    const digest = resolveDigest(image)
    if (!digest) {
      fail(
        `${SYM.fail} cannot resolve a digest for ${image}; build it with: bare scripts/build/agent.js`
      )
      Bare.exitCode = 78
      return
    }

    const ids = jobsOf(workflow, flags.job)
    if (!ids) return

    const extraEnv = {}
    for (const pair of flags.env || []) {
      const i = String(pair).indexOf('=')
      if (i <= 0) {
        fail(`--env expects KEY=VALUE, got ${JSON.stringify(pair)}`, 2)
        return
      }
      extraEnv[String(pair).slice(0, i)] = String(pair).slice(i + 1)
    }

    const caps = targets.describe({ tiers: [resolved.tier] })
    if (!asJson) {
      line(
        `${SYM.run} ${workflow.name || file}  tier=${resolved.tier}  image=${image.split('/').pop()}`
      )
    }
    emit({
      cmd: 'run',
      tag: 'start',
      data: { file, tier: resolved.tier, image, digest, jobs: ids }
    })

    let failed = false

    for (const id of ids) {
      const job = workflow.jobs[id]

      // A target this host cannot build is reported, never silently mismapped to something else --
      // wrkflw maps macos-* to a Linux image, which produces a green build of the wrong thing.
      const missing = targets.unsatisfied(caps, job.targets)
      if (missing.length === job.targets.length) {
        if (!asJson) {
          line(`  ${SYM.skip} ${id}: no buildable target here (needs ${missing.join(', ')})`)
        }
        emit({ cmd: 'job', tag: 'skipped', data: { job: id, unsatisfied: missing } })
        continue
      }
      if (missing.length && !asJson) {
        line(`  ${SYM.warn} ${id}: skipping targets not buildable here: ${missing.join(', ')}`)
      }

      const launcher = createLauncher({
        // The launcher prefixes container names with `bw-`, so do not add one here.
        jobId: `${id}-${Date.now().toString(36)}`.toLowerCase(),
        tier: resolved.tier,
        image: { ref: image.split(':')[0], digest },
        seccompProfile: SECCOMP,
        scope: false
      })

      const jobRun = createJobRun({
        job,
        launcher,
        env: { ...workflow.env, ...extraEnv }
      })

      if (asJson) {
        jobRun.on('sandbox', (data) => emit({ cmd: 'sandbox', tag: 'ready', data }))
        jobRun.on('step', (data) => emit({ cmd: 'step', tag: data.phase, data }))
        jobRun.on('stdout', (d) =>
          emit({ cmd: 'stdout', tag: String(d.index), data: d.chunk.toString() })
        )
        jobRun.on('stderr', (d) =>
          emit({ cmd: 'stderr', tag: String(d.index), data: d.chunk.toString() })
        )
      } else {
        jobRun.on('step', (d) => {
          if (d.phase === 'start') line(`  ${SYM.run} ${d.name}`)
          else {
            const sym = d.conclusion === 'success' ? SYM.ok : SYM.fail
            const why = d.timedOut
              ? ' (timed out)'
              : d.error
                ? ` (${d.error})`
                : d.code
                  ? ` (exit ${d.code})`
                  : ''
            const soft =
              d.outcome !== 'success' && d.conclusion === 'success' ? ' [continue-on-error]' : ''
            line(`  ${sym} ${d.name}  ${ms(d.ms)}${why}${soft}`)
          }
        })
        // Step output is indented so it is visibly nested under its step rather than merged into
        // the runner's own reporting.
        jobRun.on('stdout', (d) => write(indent(d.chunk.toString())))
        jobRun.on('stderr', (d) => write(indent(d.chunk.toString())))
        jobRun.on('truncated', (d) => line(`  ${SYM.warn} output truncated at ${d.limit} bytes`))
      }

      let result
      try {
        result = await jobRun.run()
      } catch (err) {
        failed = true
        if (asJson) emit({ cmd: 'job', tag: 'error', data: { job: id, error: err.message } })
        else fail(`  ${SYM.fail} ${id}: ${err.message}`)
        continue
      }

      if (result.status !== 'success') failed = true
      emit({ cmd: 'job', tag: 'end', data: result })
      if (!asJson) {
        const sym = result.status === 'success' ? SYM.ok : SYM.fail
        line(`  ${sym} job ${id}: ${result.status}`)
      }
    }

    emit({ cmd: 'run', tag: 'end', data: { ok: !failed } })
    if (failed) Bare.exitCode = 1
  }
)

function indent(text) {
  return text
    .split('\n')
    .map((l, i, arr) => (i === arr.length - 1 && l === '' ? l : '    ' + l))
    .join('\n')
}

// --- doctor ----------------------------------------------------------------------------

const doctor = command(
  'doctor',
  summary('Report isolation tiers and buildable targets for this host'),
  flag('--image <ref>', `sandbox image to check (default ${DEFAULT_IMAGE})`),
  () => {
    const image = doctor.flags.image || DEFAULT_IMAGE
    const probe = detect.probe({ image })
    const caps = targets.describe()

    line(`podman     ${probe.podman || 'not found'}`)
    line('tiers')
    for (const t of probe.tiers) {
      const status = t.available ? `${SYM.ok} available` : `${SYM.fail} ${t.reason}`
      line(`  ${t.name.padEnd(10)} rank ${String(t.rank).padEnd(4)} ${status}`)
      if (!t.available && t.remediation) line(`  ${''.padEnd(10)} fix: ${t.remediation}`)
    }
    line(`platform   ${caps.platform}-${caps.arch}  (${caps.cpus} cpus)`)
    line(`targets    ${caps.targets.join(', ')}`)
    line(`image      ${image}`)
  }
)

const cmd = command(
  'bare-workflow',
  summary('Run sandboxed workflows on Bare'),
  header('A P2P build farm for Holepunch'),
  footer('Isolation is not optional: this refuses to run rather than drop to a weaker tier.'),
  validate,
  run,
  doctor
)

module.exports = { cmd, validate, run, doctor }

if (require.main === module) {
  cmd.parse(Bare.argv.slice(2))
}
