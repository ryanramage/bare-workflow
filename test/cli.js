'use strict'

// End-to-end CLI tests: drive the real binary against the example workflows and assert on what it
// produced. This is the milestone test -- it is what makes "you can point it at a file" a claim
// with evidence behind it rather than a demo I ran once.
//
// Asserts on the --json event stream wherever possible, not on rendered text, so cosmetic output
// changes do not break the suite.

const test = require('brittle')
const { spawn } = require('bare-subprocess')
const path = require('bare-path')
const env = require('bare-env')

const detect = require('../lib/isolation/detect.js')

const ROOT = path.join(__dirname, '..')
const BIN = path.join(ROOT, 'bin.js')
const IMAGE = 'localhost/bare-workflow-base:dev'

function cli(args, timeoutMs = 300000) {
  return new Promise((resolve) => {
    const proc = spawn(Bare.argv[0], [BIN, ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR }
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      try {
        proc.kill('SIGKILL')
      } catch {}
    }, timeoutMs)
    proc.stdout.on('data', (c) => {
      stdout += c
    })
    proc.stderr.on('data', (c) => {
      stderr += c
    })
    proc.on('exit', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
  })
}

function events(stdout) {
  return stdout
    .split('\n')
    .filter((l) => l.startsWith('{'))
    .map((l) => JSON.parse(l))
}

// Can we actually run something? Probed once; every run test skips with a reason if not.
let RUNNABLE = null
function runnable() {
  if (RUNNABLE === null) {
    try {
      RUNNABLE = { ok: true, tier: detect.resolve({ min: 'container', image: IMAGE }).tier }
    } catch (err) {
      RUNNABLE = { ok: false, why: err.message.split('\n')[0] }
    }
  }
  return RUNNABLE
}

// --- validate --------------------------------------------------------------------------

test('validate accepts the examples', async (t) => {
  for (const file of ['examples/hello.yml', 'examples/hello-fails.yml', 'examples/steps.yml']) {
    const r = await cli(['validate', file], 60000)
    t.is(r.code, 0, file + ' is valid\n' + r.stderr)
  }
})

test('validate --json emits the parsed workflow', async (t) => {
  const r = await cli(['validate', 'examples/steps.yml', '--json'], 60000)
  t.is(r.code, 0)
  const out = JSON.parse(r.stdout.trim())
  t.ok(out.ok)
  t.is(out.workflow.name, 'steps')
  t.is(out.workflow.jobs.demo.steps.length, 4)
})

test('validate rejects a bad workflow with a useful message and exit 1', async (t) => {
  const fs = require('bare-fs')
  const tmp = '/tmp/bw-cli-bad-' + Date.now() + '.yml'
  fs.writeFileSync(tmp, 'version: 1\njobs:\n  a:\n    stpes: []\n')
  try {
    const r = await cli(['validate', tmp], 60000)
    t.is(r.code, 1, 'non-zero exit')
    t.ok(/did you mean "steps"/.test(r.stdout + r.stderr), 'suggests the fix')
  } finally {
    fs.unlinkSync(tmp)
  }
})

// --- doctor ----------------------------------------------------------------------------

test('doctor reports tiers and buildable targets', async (t) => {
  const r = await cli(['doctor'], 120000)
  t.is(r.code, 0)
  t.ok(/microvm/.test(r.stdout), 'names the microvm tier')
  t.ok(/container/.test(r.stdout), 'names the container tier')
  t.ok(/targets\s+host/.test(r.stdout), 'lists targets, starting with host')
})

// --- run -------------------------------------------------------------------------------

test('run executes a workflow inside a sandbox', async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const r = await cli(['run', 'examples/hello.yml', '--json', '--tier', can.tier])
  t.is(r.code, 0, 'success exits 0\n' + r.stderr)

  const evs = events(r.stdout)
  const start = evs.find((e) => e.cmd === 'run' && e.tag === 'start')
  t.ok(start, 'emitted a run/start event')
  t.is(start.data.tier, can.tier)
  t.ok(
    /^sha256:[0-9a-f]{64}$/.test(start.data.digest),
    'image is digest-pinned, not a floating tag'
  )

  const sandbox = evs.find((e) => e.cmd === 'sandbox')
  t.ok(sandbox, 'reported the sandbox it built')
  t.is(sandbox.data.agent, 'bw-agent/1')
  // The attestation is what makes a build auditable after the fact.
  t.ok(sandbox.data.attestation.argv.includes('--network'), 'attestation carries the real argv')
  t.ok(sandbox.data.attestation.image.includes('@sha256:'))

  const out = evs
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  t.ok(out.includes('hello from inside the sandbox'), 'step output was captured')

  const ends = evs.filter((e) => e.cmd === 'step' && e.tag === 'end')
  t.is(ends.length, 2, 'both steps reported')
  t.ok(
    ends.every((e) => e.data.conclusion === 'success'),
    'both succeeded'
  )
})

test('run really executes inside the sandbox, not on the host', async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }
  if (can.tier !== 'microvm') {
    t.comment('skipping: the kernel check only distinguishes host from guest on the microvm tier')
    return t.pass('skipped')
  }

  // `uname -r` inside a krun guest reports the guest kernel, which cannot be the host's. This is the
  // assertion that separates "it ran" from "it ran in the sandbox".
  const os = require('bare-os')
  const hostKernel = os.version ? os.version() : ''
  const r = await cli(['run', 'examples/hello.yml', '--json'])
  t.is(r.code, 0)
  const out = events(r.stdout)
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  const reported = out.trim().split('\n').pop().trim()
  t.ok(/^\d+\.\d+/.test(reported), 'got a kernel version: ' + reported)
  if (hostKernel) {
    t.absent(hostKernel.includes(reported), 'guest kernel differs from the host kernel')
  } else t.pass('host kernel unavailable for comparison')
})

test('a failing step fails the job, stops the run, and exits 1', async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const r = await cli(['run', 'examples/hello-fails.yml', '--json', '--tier', can.tier])
  t.is(r.code, 1, 'failure propagates to the exit code')

  const evs = events(r.stdout)
  const ends = evs.filter((e) => e.cmd === 'step' && e.tag === 'end')
  t.is(ends.length, 2, 'stopped after the failing step -- the third never ran')
  t.is(ends[1].data.code, 3, 'the real exit code is preserved')
  t.is(ends[1].data.conclusion, 'failure')

  const job = evs.find((e) => e.cmd === 'job' && e.tag === 'end')
  t.is(job.data.status, 'failure')

  const out = evs
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  t.absent(out.includes('this must never run'), 'execution stopped')
})

test('continue-on-error keeps the job going but records the real outcome', async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const r = await cli(['run', 'examples/steps.yml', '--json', '--tier', can.tier])
  t.is(r.code, 0, 'a soft failure does not fail the run')

  const evs = events(r.stdout)
  const ends = evs.filter((e) => e.cmd === 'step' && e.tag === 'end')
  t.is(ends.length, 4, 'all four steps ran')

  const soft = ends[1].data
  t.is(soft.outcome, 'failure', 'outcome records what actually happened')
  t.is(soft.conclusion, 'success', 'conclusion records what it means for the job')
  t.is(soft.code, 9)

  const out = evs
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  t.ok(out.includes('workflow=workflow job=job step=step'), 'env precedence holds end to end')
  t.ok(out.includes('carried on'), 'later steps still ran')
})

test('run refuses rather than dropping to a weaker tier', async (t) => {
  // The policy that matters most: an unavailable tier is an exit, not a silent downgrade. Exit 78
  // is EX_CONFIG -- the host is not configured to run this safely.
  const r = await cli(
    ['run', 'examples/hello.yml', '--image', 'localhost/definitely-not-built:x'],
    120000
  )
  t.is(r.code, 78, 'EX_CONFIG, not a best-effort run')
  const blob = r.stdout + r.stderr
  t.ok(/refusing to run/.test(blob), 'says it refused')
  t.ok(/fix:/.test(blob), 'and how to fix it')
})

test('an unknown job name is a usage error', async (t) => {
  const r = await cli(['run', 'examples/hello.yml', '--job', 'nope'], 120000)
  t.is(r.code, 2, 'usage errors are exit 2')
  t.ok(/no such job/.test(r.stdout + r.stderr))
})
