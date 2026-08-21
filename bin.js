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
const graph = require('./lib/graph.js')
const detect = require('./lib/isolation/detect.js')
const { create: createLauncher } = require('./lib/isolation/podman/launcher.js')
const { create: createTaskRun } = require('./lib/run')
const { localStore } = require('./lib/store')
const prefetch = require('./lib/prefetch.js')
const toolchains = require('./lib/toolchains.js')

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
  flag('--image <ref>', 'override the image for every task (normally chosen by `toolchain:`)'),
  flag('--env <pair>', 'extra KEY=VALUE for every step').multiple(),
  flag('--concurrency <n>', 'how many tasks may run at once (default 1)'),
  flag('--state <dir>', 'where artifacts and run state are kept (default .bw-state)'),
  flag('--json', 'newline-delimited JSON events instead of human output'),
  async () => {
    const { file } = run.args
    const flags = run.flags
    const asJson = !!flags.json
    const runId = Date.now().toString(36)
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

    // Pick the tier BEFORE anything else, so a machine that cannot isolate never gets as far as
    // looking like it is about to run something.
    let resolved
    try {
      resolved = detect.resolve({ min: flags.tier || 'microvm' })
    } catch (err) {
      if (asJson) {
        line(JSON.stringify({ cmd: 'error', code: err.code, error: err.message }))
      } else {
        fail(`${SYM.fail} ${err.message}`)
      }
      Bare.exitCode = 78 // EX_CONFIG: the host is not configured to run this safely
      return
    }

    let tasks
    try {
      tasks = graph.expand(workflow, { job: flags.job })
    } catch (err) {
      if (asJson) line(JSON.stringify({ cmd: 'error', code: err.code, error: err.message }))
      else fail(`${SYM.fail} ${err.message}`)
      Bare.exitCode = err.code === 'CYCLE' ? 1 : 2
      return
    }

    const extraEnv = {}
    for (const pair of flags.env || []) {
      const i = String(pair).indexOf('=')
      if (i <= 0) {
        fail(`--env expects KEY=VALUE, got ${JSON.stringify(pair)}`, 2)
        return
      }
      extraEnv[String(pair).slice(0, i)] = String(pair).slice(i + 1)
    }

    // Each job's image comes from its toolchain; --image overrides everything, which is the escape
    // hatch for an image with no registry entry yet.
    const imageFor = new Map()
    for (const task of tasks) {
      if (imageFor.has(task.job)) continue
      imageFor.set(
        task.job,
        flags.image
          ? { name: 'override', image: flags.image, build: null }
          : toolchains.forJob(workflow.jobs[task.job], workflow)
      )
    }

    // Resolve every distinct image ONCE, up front. Discovering a missing toolchain as
    // `npm: command not found` thirty seconds into a sandboxed step is a genuinely bad experience;
    // this makes it a named problem with the command that fixes it.
    const digests = new Map()
    const missing = []
    for (const chosen of imageFor.values()) {
      if (digests.has(chosen.image) || missing.some((m) => m.image === chosen.image)) continue
      const digest = resolveDigest(chosen.image)
      if (digest) digests.set(chosen.image, digest)
      else missing.push(chosen)
    }
    if (missing.length) {
      const report = [
        `${SYM.fail} required sandbox image${missing.length === 1 ? '' : 's'} not built:`
      ]
      for (const m of missing) {
        report.push(`  toolchain ${m.name}: ${m.image}`)
        if (m.build) report.push(`    build it: ${m.build}`)
      }
      if (asJson) {
        line(
          JSON.stringify({ cmd: 'error', code: 'TOOLCHAIN_NOT_BUILT', error: report.join('\n') })
        )
      } else {
        fail(report.join('\n'))
      }
      Bare.exitCode = 78
      return
    }

    const caps = targets.describe({ tiers: [resolved.tier] })
    const concurrency = Number(flags.concurrency || 1)

    // Artifacts land in a Localdrive today. The Store only knows "a drive", so the farm swaps in a
    // Hyperdrive later and artifact return from a peer becomes a mirror.
    const stateDir = path.resolve(flags.state || '.bw-state')
    const store = localStore({ root: path.join(stateDir, 'artifacts'), runId })
    const baseDir = path.dirname(path.resolve(file))

    // Prefetch on the HOST, once, before any sandbox exists. Nothing is unpacked and no package
    // code runs -- tarballs are downloaded and verified against the lockfile, and that is all.
    let cacheDir = null
    const needsPrefetch = tasks.some((t) => (workflow.jobs[t.job].prefetch || []).includes('npm'))
    if (needsPrefetch) {
      cacheDir = path.join(stateDir, 'cache', 'npm')
      const sourceDir = path.resolve(baseDir, workflow.jobs[tasks[0].job].source || '.')
      const lockPath = path.join(sourceDir, 'package-lock.json')
      let lock
      try {
        lock = fs.readFileSync(lockPath, 'utf8')
      } catch {
        fail(`${SYM.fail} prefetch declared but ${lockPath} is missing`)
        Bare.exitCode = 2
        return
      }
      try {
        const plan = prefetch.planFromLockfile(lock)
        if (!asJson) {
          line(
            `${SYM.run} prefetching ${plan.entries.length} package${plan.entries.length === 1 ? '' : 's'} from the lockfile`
          )
        }
        const result = await prefetch.run(plan, cacheDir, { fetch: httpFetch })
        emit({ cmd: 'prefetch', tag: 'end', data: result })
        if (!asJson) {
          line(`  ${SYM.ok} ${result.fetched} fetched, ${result.cached} already cached`)
        }
      } catch (err) {
        if (asJson) line(JSON.stringify({ cmd: 'error', code: err.code, error: err.message }))
        else fail(`${SYM.fail} ${err.message}`)
        Bare.exitCode = 1
        return
      }
    }

    const usedToolchains = [...new Set([...imageFor.values()].map((c) => c.name))].join(', ')
    if (!asJson) {
      line(
        `${SYM.run} ${workflow.name || file}  tier=${resolved.tier}  ` +
          `toolchain=${usedToolchains}  ${tasks.length} task${tasks.length === 1 ? '' : 's'}`
      )
    }
    emit({
      cmd: 'run',
      tag: 'start',
      data: {
        file,
        tier: resolved.tier,
        tasks: tasks.map((t) => t.id),
        toolchains: Object.fromEntries([...imageFor].map(([job, c]) => [job, c.name])),
        images: Object.fromEntries([...digests])
      }
    })

    // Completed job outputs, keyed by job then target. Kept per-target because a multi-target job
    // has one set of outputs PER target; collapsing them would invent a value.
    const jobResults = new Map()
    let failed = false

    function needsScope(task) {
      const out = {}
      for (const jobId of task.needsJobs) {
        const byTarget = jobResults.get(jobId) || new Map()
        const entries = [...byTarget.entries()]
        out[jobId] = {
          status: entries.every(([, r]) => r.status === 'success') ? 'success' : 'failure',
          // A single-target dependency resolves cleanly. Several targets is genuinely ambiguous, so
          // reading it throws rather than picking one -- silently choosing would be the sort of
          // quiet wrongness this project keeps refusing.
          outputs: entries.length === 1 ? entries[0][1].outputs : ambiguousOutputs(jobId, entries)
        }
      }
      return out
    }

    function ambiguousOutputs(jobId, entries) {
      if (entries.length === 0) return {}
      const proxy = {}
      const names = new Set()
      for (const [, r] of entries) for (const k of Object.keys(r.outputs)) names.add(k)
      for (const name of names) {
        Object.defineProperty(proxy, name, {
          enumerable: true,
          get() {
            throw new Error(
              `needs.${jobId}.outputs.${name} is ambiguous: ${jobId} ran for ${entries.length} targets ` +
                `(${entries.map(([t]) => t).join(', ')}). Give ${jobId} a single target, or read it per target.`
            )
          }
        })
      }
      return proxy
    }

    const results = await graph.schedule(
      tasks,
      async (task) => {
        const job = workflow.jobs[task.job]

        // A target this host cannot build is reported, never silently mismapped -- wrkflw maps
        // macos-* onto a Linux image, which produces a green build of the wrong thing.
        if (!targets.satisfies(caps, task.target)) {
          if (!asJson) line(`  ${SYM.skip} ${task.id}: not buildable here`)
          emit({ cmd: 'task', tag: 'unsupported', data: { task: task.id, target: task.target } })
          return { status: 'skipped', reason: 'target not buildable on this host' }
        }

        const launcher = createLauncher({
          jobId: `${task.id.replace(/[^a-z0-9-]/gi, '-')}-${Date.now().toString(36)}`.toLowerCase(),
          tier: resolved.tier,
          image: {
            ref: imageFor.get(task.job).image.split(':')[0],
            digest: digests.get(imageFor.get(task.job).image)
          },
          seccompProfile: SECCOMP,
          scope: false
        })

        const taskRun = createTaskRun({
          task,
          job,
          launcher,
          env: { ...workflow.env, ...extraEnv },
          needs: needsScope(task),
          store,
          run: { id: runId, tier: resolved.tier, state: stateDir, baseDir, cacheDir }
        })

        wire(taskRun, task, asJson, emit)

        let result
        try {
          result = await taskRun.execute()
        } catch (err) {
          if (asJson) {
            emit({ cmd: 'task', tag: 'error', data: { task: task.id, error: err.message } })
          } else {
            fail(`  ${SYM.fail} ${task.id}: ${err.message}`)
          }
          return { status: 'failure', error: err.message }
        }

        if (!jobResults.has(task.job)) jobResults.set(task.job, new Map())
        jobResults.get(task.job).set(task.target, result)

        if (!asJson) {
          const sym = result.status === 'success' ? SYM.ok : SYM.fail
          line(`  ${sym} ${task.id}: ${result.status}`)
        }
        return result
      },
      {
        concurrency,
        onSkip: (task, reason) => {
          if (!asJson) line(`  ${SYM.skip} ${task.id}: skipped (${reason})`)
          emit({ cmd: 'task', tag: 'skipped', data: { task: task.id, reason } })
        }
      }
    )

    failed = results.some((r) => r.status === 'failure')

    emit({ cmd: 'run', tag: 'end', data: { ok: !failed } })
    if (failed) Bare.exitCode = 1
  }
)

// Download a URL to a buffer. Only ever called on the host, before any sandbox exists, and only
// for URLs a committed lockfile already named.
async function httpFetch(url) {
  const fetch = require('bare-fetch')
  const res = await fetch(url)
  if (res.status !== 200) throw new Error(`HTTP ${res.status} for ${url}`)
  return Buffer.from(await res.arrayBuffer())
}

// Render or forward a task's events. Split out so the human and --json paths cannot drift.
function wire(taskRun, task, asJson, emit) {
  if (asJson) {
    // Per-task start/end, so a consumer can attribute everything else to a task. Without these the
    // stream tells you what steps ran but not which task they belonged to.
    taskRun.on('task', (data) =>
      emit({ cmd: 'task', tag: data.phase, data: { ...data, target: task.target, job: task.job } })
    )
    taskRun.on('sandbox', (data) =>
      emit({ cmd: 'sandbox', tag: 'ready', data: { task: task.id, ...data } })
    )
    taskRun.on('step', (data) =>
      emit({ cmd: 'step', tag: data.phase, data: { task: task.id, ...data } })
    )
    taskRun.on('stdout', (d) => emit({ cmd: 'stdout', tag: task.id, data: d.chunk.toString() }))
    taskRun.on('stderr', (d) => emit({ cmd: 'stderr', tag: task.id, data: d.chunk.toString() }))
    taskRun.on('warning', (d) => emit({ cmd: 'warning', tag: task.id, data: d }))
    taskRun.on('artifact', (d) =>
      emit({ cmd: 'artifact', tag: d.phase, data: { task: task.id, ...d } })
    )
    taskRun.on('source', (d) => emit({ cmd: 'source', tag: 'in', data: { task: task.id, ...d } }))
    taskRun.on('cache', (d) => emit({ cmd: 'cache', tag: 'in', data: { task: task.id, ...d } }))
    return
  }

  taskRun.on('step', (d) => {
    if (d.phase === 'start') return line(`  ${SYM.run} ${task.id} :: ${d.name}`)
    if (d.conclusion === 'skipped') {
      return line(`  ${SYM.skip} ${task.id} :: ${d.name}  (condition false)`)
    }
    const sym = d.conclusion === 'success' ? SYM.ok : SYM.fail
    const why = d.timedOut
      ? ' (timed out)'
      : d.error
        ? ` (${d.error})`
        : d.code
          ? ` (exit ${d.code})`
          : ''
    const soft = d.outcome !== 'success' && d.conclusion === 'success' ? ' [continue-on-error]' : ''
    line(`  ${sym} ${task.id} :: ${d.name}  ${ms(d.ms)}${why}${soft}`)
  })
  taskRun.on('stdout', (d) => write(indent(d.chunk.toString())))
  taskRun.on('stderr', (d) => write(indent(d.chunk.toString())))
  taskRun.on('warning', (d) => line(`  ${SYM.warn} ${d.message}`))
  taskRun.on('artifact', (d) => {
    const arrow = d.phase === 'out' ? '↑' : '↓'
    line(`  ${arrow} ${task.id} :: artifact ${d.name}  ${d.files} file${d.files === 1 ? '' : 's'}`)
  })
  taskRun.on('source', (d) => line(`  ↓ ${task.id} :: source  ${d.files} files`))
  taskRun.on('cache', (d) => line(`  ↓ ${task.id} :: cache  ${d.files} files`))
  taskRun.on('truncated', (d) => line(`  ${SYM.warn} output truncated at ${d.limit} bytes`))
}

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
  () => {
    const probe = detect.probe()
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
    line('toolchains')
    for (const name of toolchains.names()) {
      const entry = toolchains.resolve(name)
      const built = resolveDigest(entry.image)
      line(
        `  ${name.padEnd(8)} ${built ? SYM.ok + ' built    ' : SYM.fail + ' not built'} ${entry.image}`
      )
      if (!built) line(`  ${''.padEnd(8)}   build it: ${entry.build}`)
    }
  }
)

const artifacts = command(
  'artifacts',
  summary('List the artifacts a run produced'),
  arg('<run-id>', 'run id, as printed by `run --json`'),
  flag('--state <dir>', 'state directory (default .bw-state)'),
  flag('--get <name>', 'extract this artifact instead of listing'),
  flag('--to <dir>', 'where to extract it (default ./<name>)'),
  async () => {
    const stateDir = path.resolve(artifacts.flags.state || '.bw-state')
    const store = localStore({
      root: path.join(stateDir, 'artifacts'),
      runId: artifacts.args['run-id']
    })

    if (artifacts.flags.get) {
      const name = artifacts.flags.get
      const to = artifacts.flags.to || './' + name
      try {
        const got = await store.get(name, to)
        line(`${SYM.ok} ${name} -> ${got.dir}  (${got.files} files, ${got.bytes} bytes)`)
      } catch (err) {
        fail(`${SYM.fail} ${err.message}`)
      }
      return
    }

    const list = await store.list()
    if (list.length === 0) {
      line(`no artifacts for run ${artifacts.args['run-id']}`)
      return
    }
    for (const entry of list) {
      line(`  ${entry.name.padEnd(28)} ${entry.files} file${entry.files === 1 ? '' : 's'}`)
    }
  }
)

const cmd = command(
  'bare-workflow',
  summary('Run sandboxed workflows on Bare'),
  header('A P2P build farm for Holepunch'),
  footer('Isolation is not optional: this refuses to run rather than drop to a weaker tier.'),
  validate,
  run,
  doctor,
  artifacts
)

module.exports = { cmd, validate, run, doctor, artifacts }

if (require.main === module) {
  cmd.parse(Bare.argv.slice(2))
}
