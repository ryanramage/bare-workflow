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
const attestation = require('./lib/attestation.js')

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
      // A publish job described as "0 steps, targets host" would be technically true and entirely
      // unhelpful. What matters about it is that it is trusted, what it publishes, and whether it
      // would actually do so -- so say that instead.
      if (job.publish) {
        const p = job.publish
        line(
          `  job ${id}  publish ${p.artifact} -> ${p.name} via ${p.driver}` +
            `  ${p.dryRun ? '(dry-run)' : `${SYM.warn} LIVE, needs --publish`}  ${SYM.warn} not sandboxed`
        )
        continue
      }
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
  flag('--job <name>', 'run this job and everything it transitively needs'),
  flag('--tier <name>', 'minimum isolation tier: microvm (default) or container'),
  flag('--image <ref>', 'override the image for every task (normally chosen by `toolchain:`)'),
  flag('--env <pair>', 'extra KEY=VALUE for every step').multiple(),
  flag('--concurrency <n>', 'how many tasks may run at once (default 1)'),
  flag('--state <dir>', 'where artifacts and run state are kept (default .bw-state)'),
  flag('--json', 'newline-delimited JSON events instead of human output'),
  // Two independent affirmations are needed before anything is published, because publishing is the
  // only irreversible thing a run does. `dry-run: false` in the file says "this workflow is meant to
  // publish"; `--publish` on the command line says "and I mean it, now, from this machine". Either
  // one alone is a dry run. That makes a checked-in workflow safe to run for any other purpose.
  flag('--publish', 'actually publish (publish jobs are a dry run without this)'),
  flag(
    '--config <file>',
    'runner config holding named keys (default ~/.config/bare-workflow/config.json)'
  ),
  flag(
    '--bootstrap <addr>',
    'DHT bootstrap nodes, comma separated -- for a private or test network'
  ),
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
    //
    // A workflow may DECLARE its minimum (`tier: microvm`), and the strongest declaration wins:
    // a run is only as isolated as its weakest task, so the requirement has to be the maximum.
    // --tier is an explicit override for someone who accepts the risk on their own machine.
    let minTier = flags.tier || 'microvm'
    if (!flags.tier) {
      const declared = Object.values(workflow.jobs)
        .map((j) => j.tier)
        .filter(Boolean)
      if (declared.length) {
        minTier = declared.reduce((a, b) => (detect.RANK[b] > detect.RANK[a] ? b : a))
      }
    }

    let resolved
    try {
      resolved = detect.resolve({ min: minTier })
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

    // The upgrade link is compiled into the binary (bin.mjs imports package.json), so a
    // distributable is only publishable against the link it was built with. Assert it before
    // anything runs -- and never write it, so the runner stays a build tool and the attestation keeps
    // describing exactly what was in the tree.
    if (workflow.expect && workflow.expect.upgrade) {
      const pkgPath = path.join(path.resolve(baseDir, workflow.source || '.'), 'package.json')
      let found = null
      try {
        found = JSON.parse(fs.readFileSync(pkgPath, 'utf8')).upgrade || null
      } catch {
        fail(`${SYM.fail} expect.upgrade is declared but ${pkgPath} could not be read`)
        Bare.exitCode = 2
        return
      }
      if (found !== workflow.expect.upgrade) {
        const message =
          `${SYM.fail} upgrade link mismatch in ${pkgPath}\n` +
          `  expected  ${workflow.expect.upgrade}\n` +
          `  found     ${found === null ? '(no "upgrade" field)' : found}\n` +
          '  the link is compiled into the binary, so building against the wrong one produces a\n' +
          '  distributable that cannot receive updates from the intended release line.'
        if (asJson) line(JSON.stringify({ cmd: 'error', code: 'UPGRADE_MISMATCH', error: message }))
        else fail(message)
        Bare.exitCode = 1
        return
      }
    }

    // Resolve every publish key BEFORE anything runs. A publish job is the last thing in a release
    // pipeline, so a missing config would otherwise surface after six targets have been built --
    // twenty minutes of correct work thrown away over a line of JSON. Same reasoning as the image
    // preflight above, and the same exit code: this is a host configuration problem, not a bad
    // workflow. Only the presence and shape of the key is checked; its value is never touched here.
    //
    // Deliberately AFTER the `expect.upgrade` assertion: that one is a problem in the repository,
    // which the author can fix and probably introduced; this one is a problem with the machine. When
    // both are wrong, the repository error is the more useful thing to hear first.
    const publishJobs = Object.values(workflow.jobs).filter((j) => j.publish)
    if (publishJobs.length) {
      const configLib = require('./lib/config.js')
      const driverLib = require('./lib/publish/pear-ci.js')
      try {
        const cfg = configLib.load(flags.config)
        for (const job of publishJobs) {
          driverLib.parsePrimaryKey(cfg.secret(job.publish.key, 'primaryKey'), `jobs.${job.id}`)
        }
      } catch (err) {
        const message =
          `${SYM.fail} ${err.message}\n` +
          `  needed by publish job${publishJobs.length === 1 ? '' : 's'}: ` +
          publishJobs.map((j) => `${j.id} (key: ${j.publish.key})`).join(', ')
        if (asJson) {
          line(JSON.stringify({ cmd: 'error', code: err.code || 'CONFIG_MISSING', error: message }))
        } else {
          fail(message)
        }
        Bare.exitCode = 78
        return
      }
    }

    // Prefetch on the HOST, once, before any sandbox exists. Nothing is unpacked and no package
    // code runs -- tarballs are downloaded and verified against the lockfile, and that is all.
    let cacheDir = null
    const prefetchers = new Set(tasks.flatMap((t) => workflow.jobs[t.job].prefetch || []))
    const needsPrefetch = prefetchers.has('npm') || prefetchers.has('npm-dev')
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
        const plan = prefetch.planFromLockfile(lock, { includeDev: prefetchers.has('npm-dev') })
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

    const attestations = []
    // Source provenance is captured once per run: it cannot change mid-run, and shelling git per
    // task would be noise.
    const sourceFacts = attestation.sourceFacts(
      workflow.source ? path.resolve(baseDir, workflow.source) : baseDir,
      (file2, args) => {
        const { spawnSync } = require('bare-subprocess')
        const r = spawnSync(file2, args, { env: { PATH: env.PATH, HOME: env.HOME } })
        return r.status === 0 && r.stdout ? r.stdout.toString() : null
      }
    )

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

        // A publish job never enters a sandbox -- see lib/publish for why that is the design and not
        // a shortcut. It is handled before any of the isolation machinery below, so there is no path
        // by which a publish acquires an image, a workspace, or a step to run.
        if (job.publish) {
          return await runPublishTask({
            task,
            job,
            store,
            runId,
            stateDir,
            file,
            workflow,
            flags,
            asJson,
            emit,
            line,
            attestations
          })
        }

        // A target this host cannot build is reported, never silently mismapped -- wrkflw maps
        // macos-* onto a Linux image, which produces a green build of the wrong thing.
        if (!targets.satisfies(caps, task.target)) {
          if (!asJson) line(`  ${SYM.skip} ${task.id}: not buildable here`)
          emit({ cmd: 'task', tag: 'unsupported', data: { task: task.id, target: task.target } })
          return { status: 'skipped', reason: 'target not buildable on this host' }
        }

        const chosen = imageFor.get(task.job)
        const launcher = createLauncher({
          jobId: `${task.id.replace(/[^a-z0-9-]/gi, '-')}-${Date.now().toString(36)}`.toLowerCase(),
          tier: resolved.tier,
          image: { ref: chosen.image.split(':')[0], digest: digests.get(chosen.image) },
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

        // Write the record for EVERY task, including a failed one -- an attestation that only
        // exists on success tells you nothing about the run you actually want to inspect.
        const record = attestation.forTask({
          run: { id: runId, workflow: workflow.name, file },
          task,
          job,
          result,
          isolation: {
            tier: resolved.tier,
            image: `${chosen.image.split(':')[0]}@${digests.get(chosen.image)}`,
            seccompProfile: SECCOMP,
            program: launcher.built.program,
            argv: launcher.built.argv,
            agent: result.agent || null
          },
          source: sourceFacts,
          prefetch: job.prefetch || [],
          artifacts: (result.artifacts || []).map((a) => ({
            name: a.name,
            files: a.files,
            bytes: a.bytes,
            digest: a.digest || null
          })),
          versions: { podman: resolved.podman || null }
        })
        const written = attestation.write(stateDir, record)
        attestations.push({
          task: task.id,
          status: result.status,
          file: written.file,
          sha256: written.sha256
        })
        emit({ cmd: 'attestation', tag: 'written', data: { task: task.id, ...written } })

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

    const summary = {
      version: attestation.VERSION,
      run: { id: runId, workflow: workflow.name, file, tier: resolved.tier, minTier },
      createdAt: new Date().toISOString(),
      host: attestation.hostFacts({ podman: resolved.podman || null }),
      source: sourceFacts,
      images: Object.fromEntries([...digests]),
      status: failed ? 'failure' : 'success',
      tasks: results.map((r) => ({ id: r.id, status: r.status })),
      attestations
    }
    attestation.writeSummary(stateDir, summary)
    if (!asJson) line(`  ${SYM.ok} attestation: ${stateDir}/runs/${runId}/`)

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

// Human-readable bytes. Binary units, because that is what the limits are expressed in.
function size(bytes) {
  const units = ['B', 'KiB', 'MiB', 'GiB']
  let n = Number(bytes) || 0
  let i = 0
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024
    i++
  }
  return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i]
}

function indent(text) {
  return text
    .split('\n')
    .map((l, i, arr) => (i === arr.length - 1 && l === '' ? l : '    ' + l))
    .join('\n')
}

// --- publish ---------------------------------------------------------------------------

// The trusted half of a run. Everything here is deliberately outside the sandbox machinery: no
// launcher, no image, no workspace, no step. Its only input is an artifact the store already holds
// and has already digest-bound, and its only secret comes from runner config the workflow cannot
// read.
async function runPublishTask(ctx) {
  const { task, job, store, runId, stateDir, file, workflow, flags, asJson, emit, line } = ctx
  const spec = job.publish

  // Both affirmations, or it is a dry run. Stated as an explicit boolean rather than folded into the
  // driver call, because it is also what gets recorded and printed -- and "did this really publish"
  // must never be a matter of inference.
  const live = spec.dryRun === false && !!flags.publish
  const why = spec.dryRun !== false ? 'dry-run is set in the workflow' : 'no --publish on this run'

  const driver = require('./lib/publish/pear-ci.js')
  const configLib = require('./lib/config.js')

  let extracted = null
  try {
    // The key is needed even for a dry run: the drive's identity is derived from it, so without it
    // there is no link to diff against and nothing meaningful to preview.
    const config = configLib.load(flags.config)
    const primaryKey = config.secret(spec.key, 'primaryKey')

    extracted = path.join(stateDir, 'runs', String(runId), 'publish-' + spec.artifact)
    fs.rmSync(extracted, { recursive: true, force: true })
    const artifact = await store.get(spec.artifact, extracted)

    // Snapshot: DURABLE, shared across runs in this state directory. Storage: throwaway, which is
    // what "stateless stage" means -- the cores are re-derived from the key and re-synced from peers
    // to the lengths the snapshot records.
    const snapshot = path.join(stateDir, 'pear', spec.name, 'snapshot.json')
    const storage = path.join(stateDir, 'runs', String(runId), 'pear-storage-' + spec.name)

    if (!asJson) {
      line(
        `  ${SYM.run} ${task.id} :: ${live ? 'publishing' : 'DRY RUN'} ${spec.artifact} -> ${spec.name}`
      )
      if (!live) line(`    not publishing: ${why}`)
    }
    emit({
      cmd: 'publish',
      tag: 'start',
      data: { task: task.id, driver: spec.driver, name: spec.name, artifact: spec.artifact, live }
    })

    const result = await driver.publish({
      primaryKey,
      name: spec.name,
      dir: extracted,
      snapshot,
      storage,
      dryRun: !live,
      bootstrap: parseBootstrap(flags.bootstrap),
      onDiff: (diff) => {
        if (!asJson) line(`    ${diff.op} ${diff.key}`)
      }
    })

    // The link is the answer to "where did this go", so it is printed whether or not this was live --
    // a dry run that cannot tell you the target is not much of a preview.
    if (!asJson) {
      line(`  ${SYM.ok} ${task.id}: ${live ? 'published' : 'would publish'} ${result.link}`)
      line(
        `    ${result.changed} entr${result.changed === 1 ? 'y' : 'ies'} changed, snapshot length ${result.snapshot.before.length} -> ${result.snapshot.after.length}`
      )
    }
    emit({ cmd: 'publish', tag: 'done', data: { task: task.id, ...result, live } })

    const record = attestation.forPublish({
      run: { id: runId, workflow: workflow.name, file },
      task,
      job,
      result: { status: 'success' },
      artifact: { name: spec.artifact, digest: artifact.digest || null, files: artifact.files },
      publish: { ...result, live, key: spec.key },
      versions: {}
    })
    const written = attestation.write(stateDir, record)
    ctx.attestations.push({
      task: task.id,
      status: 'success',
      file: written.file,
      sha256: written.sha256
    })
    emit({ cmd: 'attestation', tag: 'written', data: { task: task.id, ...written } })

    return { status: 'success', publish: result, steps: [], artifacts: [] }
  } catch (err) {
    if (asJson) emit({ cmd: 'publish', tag: 'error', data: { task: task.id, error: err.message } })
    else fail(`  ${SYM.fail} ${task.id}: ${err.message}`)
    return { status: 'failure', error: err.message }
  } finally {
    // The extracted tree is a copy of an artifact the store still holds, and the corestore storage is
    // throwaway by design. Neither is worth keeping, and the storage in particular would otherwise
    // grow a full drive copy per run.
    for (const dir of [
      extracted,
      path.join(stateDir, 'runs', String(runId), 'pear-storage-' + spec.name)
    ]) {
      if (!dir) continue
      try {
        fs.rmSync(dir, { recursive: true, force: true })
      } catch {}
    }
  }
}

function parseBootstrap(raw) {
  if (!raw) return undefined
  return String(raw)
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((entry) => {
      const i = entry.lastIndexOf(':')
      if (i === -1) return { host: entry, port: 49737 }
      return { host: entry.slice(0, i), port: Number(entry.slice(i + 1)) }
    })
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
        `  ${name.padEnd(11)} ${built ? SYM.ok + ' built    ' : SYM.fail + ' not built'} ${entry.image}`
      )
      if (!built) line(`  ${''.padEnd(11)}   build it: ${entry.build}`)
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
      runId: artifacts.args.runId
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
      line(`no artifacts for run ${artifacts.args.runId}`)
      return
    }
    for (const entry of list) {
      const files = `${entry.files} file${entry.files === 1 ? '' : 's'}`
      line(`  ${entry.name.padEnd(24)} ${files.padStart(8)}  ${size(entry.bytes).padStart(9)}`)
    }
    // A distributable is ~80 MB, so a listing without sizes hides the one number you would use it
    // to check. The digest is deliberately not here: computing it means reading every byte, and
    // `attest` already reports it from the record.
    line(
      `  ${''.padEnd(24)} ${String(list.length).padStart(8)}  ${size(list.reduce((n, e) => n + e.bytes, 0)).padStart(9)}  total`
    )
  }
)

const attest = command(
  'attest',
  summary('Show what a run actually did, and under what isolation'),
  arg('<run-id>', 'run id, as printed at the end of a run'),
  flag('--state <dir>', 'state directory (default .bw-state)'),
  flag('--task <id>', 'show the full record for one task'),
  flag('--json', 'raw records'),
  () => {
    const stateDir = path.resolve(attest.flags.state || '.bw-state')
    const { summary: sum, tasks } = attestation.read(stateDir, attest.args.runId)

    if (!sum && tasks.length === 0) {
      fail(`${SYM.fail} no attestation for run ${attest.args.runId} under ${stateDir}`)
      return
    }

    if (attest.flags.task) {
      const record = tasks.find((x) => x.task.id === attest.flags.task)
      if (!record) {
        fail(
          `${SYM.fail} no such task ${JSON.stringify(attest.flags.task)} in run ${attest.args.runId}`
        )
        return
      }
      line(JSON.stringify(record, null, 2))
      return
    }

    if (attest.flags.json) {
      line(JSON.stringify({ summary: sum, tasks }, null, 2))
      return
    }

    if (sum) {
      line(`run        ${sum.run.id}  ${sum.status}`)
      line(`workflow   ${sum.run.workflow || sum.run.file}`)
      line(
        `tier       ${sum.run.tier}${sum.run.minTier ? `  (minimum required: ${sum.run.minTier})` : ''}`
      )
      if (sum.source && sum.source.commit) {
        line(`source     ${sum.source.commit.slice(0, 12)}${sum.source.dirty ? ' (dirty)' : ''}`)
      }
      for (const [image, digest] of Object.entries(sum.images || {})) {
        line(`image      ${image}@${digest.slice(0, 19)}...`)
      }
    }
    line('tasks')
    for (const record of tasks) {
      const sym = record.status === 'success' ? SYM.ok : SYM.fail
      line(`  ${sym} ${record.task.id.padEnd(24)} ${record.isolation.tier}`)
      if (record.isolation.seccomp) {
        line(
          `    ${''.padEnd(24)} seccomp ${String(record.isolation.seccomp.sha256).slice(0, 16)}...`
        )
      }
      for (const a of record.outputs.artifacts || []) {
        line(
          `    ↑ ${a.name.padEnd(22)} ${a.files} files  ${a.digest ? a.digest.slice(0, 19) + '...' : ''}`
        )
      }
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
  artifacts,
  attest
)

module.exports = { cmd, validate, run, doctor, artifacts, attest }

if (require.main === module) {
  cmd.parse(Bare.argv.slice(2))
}
