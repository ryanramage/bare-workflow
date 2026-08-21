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

// Container-backed tests carry an explicit timeout: every task boots its own sandbox, so a
// multi-task graph comfortably exceeds brittle's 30s default -- especially with several test files
// running concurrently.
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
  for (const file of [
    'examples/hello.yml',
    'examples/hello-fails.yml',
    'examples/steps.yml',
    'examples/graph.yml',
    'examples/fanout.yml',
    'examples/artifacts.yml',
    'examples/offline.yml'
  ]) {
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

test('run executes a workflow inside a sandbox', { timeout: 240000 }, async (t) => {
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
  // Images are per-toolchain now, and every one of them is digest-pinned: a floating tag would let
  // whoever controls the registry change what an attestation refers to.
  const pinned = Object.values(start.data.images)
  t.ok(pinned.length > 0, 'at least one image was resolved')
  t.ok(
    pinned.every((d) => /^sha256:[0-9a-f]{64}$/.test(d)),
    'every image is digest-pinned, not a floating tag'
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

test('run really executes inside the sandbox, not on the host', { timeout: 240000 }, async (t) => {
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

test('a failing step fails the job, stops the run, and exits 1', { timeout: 240000 }, async (t) => {
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

  // Events are per-TASK now that a job fans out across targets.
  const task = evs.find((e) => e.cmd === 'task' && e.tag === 'end')
  t.is(task.data.status, 'failure')

  const out = evs
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  t.absent(out.includes('this must never run'), 'execution stopped')
})

test(
  'continue-on-error keeps the job going but records the real outcome',
  { timeout: 240000 },
  async (t) => {
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
  }
)

test('run refuses when it cannot get an image, rather than trying anyway', async (t) => {
  // An unusable image is an exit, not a best-effort run. Exit 78 is EX_CONFIG: the host is not set
  // up, which is deliberately a different thing from the build having failed.
  //
  // Note this exercises the IMAGE path, not the tier path -- tier detection no longer takes an
  // image, and the tier refusal is covered in test/detect.js where availability can be controlled.
  const r = await cli(
    ['run', 'examples/hello.yml', '--image', 'localhost/definitely-not-built:x'],
    120000
  )
  t.is(r.code, 78, 'EX_CONFIG, not a best-effort run')
  const blob = r.stdout + r.stderr
  t.ok(/not built/.test(blob), 'says the image is missing')
  t.ok(/localhost\/definitely-not-built/.test(blob), 'and names it')
})

test('an unknown job name is a usage error', async (t) => {
  const r = await cli(['run', 'examples/hello.yml', '--job', 'nope'], 120000)
  t.is(r.code, 2, 'usage errors are exit 2')
  t.ok(/no such job/.test(r.stdout + r.stderr))
})

// --- M2: the graph -------------------------------------------------------------------

test('an output flows from one job to the next', { timeout: 240000 }, async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const r = await cli(['run', 'examples/graph.yml', '--json', '--tier', can.tier])
  t.is(r.code, 0, 'the run succeeded\n' + r.stderr)

  const evs = events(r.stdout)
  const out = evs
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  // The whole point of M2: the value was produced by one job, written to a file, parsed on the
  // trusted side, and interpolated into a later job's command.
  t.ok(out.includes('packaging 1.2.3'), 'the downstream job saw the upstream output')

  const versionTask = evs.find(
    (e) => e.cmd === 'task' && e.tag === 'end' && e.data.task === 'version:host'
  )
  t.is(versionTask.data.outputs.value, '1.2.3', 'the declared job output was resolved')
})

test('conditions are evaluated, not merely parsed', { timeout: 240000 }, async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const r = await cli(['run', 'examples/graph.yml', '--json', '--tier', can.tier])
  const evs = events(r.stdout)
  const ends = evs.filter(
    (e) => e.cmd === 'step' && e.tag === 'end' && e.data.task === 'notify:host'
  )

  t.is(ends.length, 2, 'both steps were considered')
  t.is(ends[0].data.conclusion, 'success', 'if: success() ran')
  t.is(ends[1].data.conclusion, 'skipped', 'if: failure() was skipped, not silently run')

  const out = evs
    .filter((e) => e.cmd === 'stdout')
    .map((e) => e.data)
    .join('')
  t.absent(out.includes('should not print'), 'the skipped step really did not execute')
})

test(
  'a job fans out to one task per target, skipping what this host cannot build',
  { timeout: 240000 },
  async (t) => {
    const can = runnable()
    if (!can.ok) {
      t.comment('skipping: ' + can.why)
      return t.pass('skipped')
    }

    const r = await cli([
      'run',
      'examples/fanout.yml',
      '--json',
      '--concurrency',
      '4',
      '--tier',
      can.tier
    ])
    t.is(r.code, 0)

    const evs = events(r.stdout)
    const start = evs.find((e) => e.cmd === 'run' && e.tag === 'start')
    t.is(start.data.tasks.length, 5, '4 build targets + 1 assemble')

    // Unsupported targets are REPORTED. wrkflw maps macos-* onto a Linux image, which produces a
    // green build of the wrong thing -- strictly worse than an honest skip.
    const unsupported = evs
      .filter((e) => e.cmd === 'task' && e.tag === 'unsupported')
      .map((e) => e.data.target)
    t.ok(unsupported.includes('darwin-arm64'), 'darwin is not buildable on a linux host')
    t.ok(unsupported.includes('win32-x64'), 'nor is windows')

    const out = evs
      .filter((e) => e.cmd === 'stdout')
      .map((e) => e.data)
      .join('')
    t.ok(out.includes('building linux / x64'), '{{ target }} was interpolated per task')
    t.ok(out.includes('building linux / arm64'), 'and differs between tasks')
  }
)

test('a failing task skips its dependents', { timeout: 240000 }, async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const fs = require('bare-fs')
  const tmp = '/tmp/bw-cli-cascade-' + Date.now() + '.yml'
  fs.writeFileSync(
    tmp,
    [
      'version: 1',
      'targets: [host]',
      'jobs:',
      '  upstream:',
      '    steps: [exit 4]',
      '  downstream:',
      '    needs: upstream',
      '    steps: [echo NEVER]'
    ].join('\n') + '\n'
  )
  try {
    const r = await cli(['run', tmp, '--json', '--tier', can.tier])
    t.is(r.code, 1, 'the run failed')
    const evs = events(r.stdout)
    const skipped = evs.find((e) => e.cmd === 'task' && e.tag === 'skipped')
    t.ok(skipped, 'the dependent was skipped')
    t.ok(
      /upstream/.test(skipped.data.reason),
      'and the reason names the cause: ' + skipped.data.reason
    )
    const out = evs
      .filter((e) => e.cmd === 'stdout')
      .map((e) => e.data)
      .join('')
    t.absent(out.includes('NEVER'), 'it really did not run')
  } finally {
    fs.unlinkSync(tmp)
  }
})

test('a dependency cycle is refused before anything runs', async (t) => {
  const fs = require('bare-fs')
  const tmp = '/tmp/bw-cli-cycle-' + Date.now() + '.yml'
  fs.writeFileSync(
    tmp,
    'version: 1\njobs:\n  a:\n    needs: b\n    steps: [x]\n  b:\n    needs: a\n    steps: [x]\n'
  )
  try {
    const r = await cli(['run', tmp], 120000)
    t.is(r.code, 1)
    t.ok(/dependency cycle: a -> b -> a/.test(r.stdout + r.stderr), 'names the cycle')
  } finally {
    fs.unlinkSync(tmp)
  }
})

test('an ambiguous multi-target output is refused, not guessed', { timeout: 240000 }, async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  // A job that ran for two targets has two sets of outputs. Picking one silently is exactly the
  // kind of quiet wrongness this project keeps refusing.
  const fs = require('bare-fs')
  const tmp = '/tmp/bw-cli-ambig-' + Date.now() + '.yml'
  fs.writeFileSync(
    tmp,
    [
      // Block style, not flow style. `{{` opens a YAML flow mapping, so an interpolation inside
      // a flow sequence (`steps: [echo '{{ x }}']`) is a syntax error -- which is how this
      // fixture failed the first time, looking exactly like a broken feature.
      'version: 1',
      'jobs:',
      '  multi:',
      '    targets: [linux-x64, linux-arm64]',
      '    outputs:',
      "      value: '{{ steps.s.outputs.v }}'",
      '    steps:',
      '      - id: s',
      '        run: echo "v=from-{{ target }}" >> $BW_OUTPUT',
      '  consumer:',
      '    needs: multi',
      '    targets: [host]',
      '    steps:',
      "      - run: echo 'got {{ needs.multi.outputs.value }}'"
    ].join('\n') + '\n'
  )
  try {
    const r = await cli(['run', tmp, '--json', '--concurrency', '2', '--tier', can.tier])
    t.is(r.code, 1, 'the run failed rather than picking a value')
    const blob = r.stdout + r.stderr
    t.ok(/ambiguous/.test(blob), 'says it is ambiguous')
    t.ok(/2 targets/.test(blob), 'and how many targets produced it')
  } finally {
    fs.unlinkSync(tmp)
  }
})

// --- M4: artifacts and offline installs ------------------------------------------------

test('artifacts flow between jobs, one per target', { timeout: 300000 }, async (t) => {
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const fsx = require('bare-fs')
  const state = '/tmp/bw-cli-artifacts-' + Date.now()
  try {
    const r = await cli(
      [
        'run',
        'examples/artifacts.yml',
        '--json',
        '--concurrency',
        '2',
        '--state',
        state,
        '--tier',
        can.tier
      ],
      300000
    )
    t.is(r.code, 0, 'the run succeeded\n' + r.stderr)

    const evs = events(r.stdout)
    const out = evs.filter((e) => e.cmd === 'artifact' && e.tag === 'out').map((e) => e.data.name)
    // The name is interpolated, so a fan-out job produces one artifact per target rather than four
    // tasks fighting over a single name.
    t.ok(out.includes('app-linux-x64'), 'per-target artifact for x64')
    t.ok(out.includes('app-linux-arm64'), 'and for arm64')
    t.ok(out.includes('bundle'), 'plus the assembled bundle')

    const ins = evs.filter((e) => e.cmd === 'artifact' && e.tag === 'in').map((e) => e.data.name)
    t.is(ins.length, 2, 'the assemble job consumed both')

    const stdout = evs
      .filter((e) => e.cmd === 'stdout')
      .map((e) => e.data)
      .join('')
    t.ok(stdout.includes('binary for linux-x64'), 'and actually read their contents')
    t.ok(stdout.includes('binary for linux-arm64'))
  } finally {
    try {
      fsx.rmSync(state, { recursive: true, force: true })
    } catch {}
  }
})

test(
  'an empty artifact fails the task when if-no-files-found is error',
  { timeout: 240000 },
  async (t) => {
    const can = runnable()
    if (!can.ok) {
      t.comment('skipping: ' + can.why)
      return t.pass('skipped')
    }
    const fsx = require('bare-fs')
    const tmpf = '/tmp/bw-cli-empty-artifact-' + Date.now() + '.yml'
    const state = '/tmp/bw-cli-empty-state-' + Date.now()
    fsx.writeFileSync(
      tmpf,
      [
        'version: 1',
        'jobs:',
        '  a:',
        '    targets: [host]',
        '    artifacts:',
        '      out:',
        '        - name: nothing',
        '          path: does-not-exist/**',
        '          if-no-files-found: error',
        '    steps:',
        '      - run: echo did nothing'
      ].join('\n') + '\n'
    )
    try {
      const r = await cli(['run', tmpf, '--json', '--state', state, '--tier', can.tier], 240000)
      t.is(r.code, 1, 'publishing nothing is a failure when declared so')
      t.ok(/ARTIFACT|matched no files|no such path/.test(r.stdout + r.stderr), 'and it says why')
    } finally {
      try {
        fsx.unlinkSync(tmpf)
        fsx.rmSync(state, { recursive: true, force: true })
      } catch {}
    }
  }
)

test('a missing toolchain image fails before anything runs', { timeout: 120000 }, async (t) => {
  // The trap this replaced: without a declared toolchain the base image has no npm, and the failure
  // surfaced as `npm: command not found` inside a sandbox rather than as a named, fixable problem.
  const fsx = require('bare-fs')
  const tmpf = '/tmp/bw-cli-toolchain-' + Date.now() + '.yml'
  fsx.writeFileSync(tmpf, 'version: 1\ntoolchain: node\nsteps:\n  - npm -v\n')
  try {
    const r = await cli(['run', tmpf, '--image', 'localhost/definitely-not-built:x'], 120000)
    t.is(r.code, 78, 'EX_CONFIG: the host is not set up, which is not the same as a failed build')
    t.ok(/not built/.test(r.stdout + r.stderr), 'says the image is missing')
  } finally {
    try {
      fsx.unlinkSync(tmpf)
    } catch {}
  }
})

test('the offline example runs with no flags at all', { timeout: 300000 }, async (t) => {
  // This is the regression guard for the reported bug: `bare bin.js run examples/offline.yml` with
  // nothing else must work, because the workflow declares `toolchain: node` itself.
  const can = runnable()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }
  const detectLib = require('../lib/isolation/detect.js')
  const toolchains = require('../lib/toolchains.js')
  const fsx = require('bare-fs')
  const state = '/tmp/bw-cli-offline-' + Date.now()

  // Skip rather than fail if the node toolchain has not been built on this machine.
  const probe = detectLib.probe({ image: toolchains.resolve('node').image })
  if (probe.tiers.every((x) => !x.available)) {
    t.comment('skipping: the node toolchain image is not built')
    return t.pass('skipped')
  }

  try {
    const r = await cli(['run', 'examples/offline.yml', '--json', '--state', state], 300000)
    if (r.code === 78 && /not built/.test(r.stdout + r.stderr)) {
      t.comment('skipping: node toolchain image not built')
      return t.pass('skipped')
    }
    t.is(r.code, 0, 'no flags needed\n' + r.stderr)

    const evs = events(r.stdout)
    const start = evs.find((e) => e.cmd === 'run' && e.tag === 'start')
    t.is(start.data.toolchains.test, 'node', 'the workflow chose its own toolchain')

    const out = evs
      .filter((e) => e.cmd === 'stdout')
      .map((e) => e.data)
      .join('')
    t.ok(out.includes('confirmed: no default route'), 'and it really had no network')
    t.ok(out.includes('dependency works offline'), 'while still installing and using a dependency')
  } finally {
    try {
      fsx.rmSync(state, { recursive: true, force: true })
    } catch {}
  }
})
