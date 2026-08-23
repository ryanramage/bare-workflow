'use strict'

// Schema tests. Pure -- no YAML files on disk, no IO.
//
// Heavy on the NEGATIVE cases on purpose. GHA's habit of accepting a typo and then silently doing
// nothing is the single largest source of mystery CI failures, so "this is rejected, with a useful
// message" is the feature being tested here, not an afterthought.

const test = require('brittle')
const { parse, SCHEMA_VERSION, DEFAULT_JOB } = require('../lib/schema')

const ok = (src) => parse(src, { filename: 'w.yml' })

function rejects(t, src, pattern, why) {
  try {
    parse(src, { filename: 'w.yml' })
    t.fail('should have been rejected: ' + why)
  } catch (err) {
    t.ok(pattern.test(err.message), `${why}\n    got: ${err.message}`)
  }
}

test('the tier vocabulary is one list, not three that drift', (t) => {
  // Three modules need to know the tier names: the registry in detect.js (which owns the ranks), the
  // argv builder, and the schema. They were three separate literals, and it went wrong exactly as you
  // would expect -- the `machine` tier was added to the registry and to argv but not to the schema, so
  // `--tier machine` worked on the command line while a workflow declaring `tier: machine` was
  // rejected as unknown. Decision 8 makes that more than a papercut: the declared tier is part of the
  // contract `plan --json` is supposed to show in full, so a Mac user could not state the boundary
  // their build required.
  //
  // The schema now derives its list. This asserts argv has not drifted from the registry either.
  const detect = require('../lib/isolation/detect.js')
  const argv = require('../lib/isolation/podman/argv.js')
  const schema = require('../lib/schema')

  const registry = detect.TIERS.map((x) => x.name)

  // The schema must know EVERY registered tier -- anything less and a tier is selectable with --tier
  // but not declarable in a workflow, which is the `machine` bug described above.
  t.alike([...schema.TIERS].sort(), [...registry].sort(), 'schema knows every registered tier')

  // argv is a SUBSET, and deliberately so: it builds podman command lines, and `seatbelt` is not a
  // podman tier at all -- it is a native Seatbelt process with its own launcher. What must hold is
  // that argv never names a tier the registry does not, which would be a tier nothing can select.
  for (const tier of argv.TIERS) {
    t.ok(registry.includes(tier), `argv's ${tier} is a registered tier`)
  }

  // And the vocabulary is actually usable end to end, which is the thing that was broken.
  for (const tier of registry) {
    t.execution(
      () => ok(`version: 1\ntier: ${tier}\nsteps:\n  - echo ok\n`),
      `a workflow can declare tier: ${tier}`
    )
  }
})

test('the minimal workflow parses', (t) => {
  const w = ok('version: 1\nsteps:\n  - echo hi\n')
  t.is(w.version, SCHEMA_VERSION)
  t.ok(w.desugared, 'top-level steps is recorded as sugar')
  t.alike(Object.keys(w.jobs), [DEFAULT_JOB])
  t.is(w.jobs.main.steps.length, 1)
  t.is(w.jobs.main.steps[0].run, 'echo hi')
})

test('a six-line workflow stays six lines', (t) => {
  // The whole pitch versus a GHA file. If this ever needs a `jobs:` wrapper, the pitch is gone.
  const w = ok(
    ['version: 1', 'targets:', '  - linux-x64', 'steps:', '  - npm ci', '  - npm test'].join('\n')
  )
  t.alike(w.targets, ['linux-x64'])
  t.is(w.jobs.main.steps.length, 2)
  t.alike(w.jobs.main.targets, ['linux-x64'], 'the job inherits workflow targets')
})

test('both step forms normalize to one shape', (t) => {
  // If they did not, every consumer would handle two shapes and step.shell would be undefined half
  // the time.
  const a = ok('version: 1\nsteps:\n  - echo hi\n').jobs.main.steps[0]
  const b = ok('version: 1\nsteps:\n  - run: echo hi\n').jobs.main.steps[0]
  t.alike(Object.keys(a).sort(), Object.keys(b).sort(), 'identical key sets')
  t.is(a.shell, 'bash')
  t.is(a.timeoutMs, 0)
  t.is(a.continueOnError, false)
  t.is(a.name, 'echo hi', 'the command becomes the display name')
})

test('the full step form is carried through', (t) => {
  const w = ok(
    [
      'version: 1',
      'steps:',
      '  - name: build it',
      '    id: build',
      '    run: make',
      '    shell: sh',
      '    cwd: /w/src/sub',
      '    timeout: 20m',
      '    continue-on-error: true',
      '    env:',
      '      K: v'
    ].join('\n')
  )
  const s = w.jobs.main.steps[0]
  t.is(s.name, 'build it')
  t.is(s.id, 'build')
  t.is(s.shell, 'sh')
  t.is(s.cwd, '/w/src/sub')
  t.is(s.timeoutMs, 20 * 60 * 1000)
  t.is(s.continueOnError, true)
  t.alike(s.env, { K: 'v' })
})

test('durations accept the units humans write', (t) => {
  const ms = (v) =>
    ok(`version: 1\nsteps:\n  - run: x\n    timeout: ${v}\n`).jobs.main.steps[0].timeoutMs
  t.is(ms('500ms'), 500)
  t.is(ms('30s'), 30000)
  t.is(ms('20m'), 1200000)
  t.is(ms('1h'), 3600000)
  t.is(ms(45), 45000, 'a bare number is seconds')
})

test('env values are stringified, keys are validated', (t) => {
  const w = ok('version: 1\nenv:\n  N: 3\n  B: true\n  S: hi\nsteps:\n  - echo\n')
  t.alike(w.env, { N: '3', B: 'true', S: 'hi' }, 'YAML scalars become strings')
  rejects(
    t,
    'version: 1\nenv:\n  BAD-KEY: 1\nsteps:\n  - echo\n',
    /valid identifiers/,
    'dashed env name'
  )
  rejects(
    t,
    'version: 1\nenv:\n  K: {a: 1}\nsteps:\n  - echo\n',
    /must be a string/,
    'mapping env value'
  )
})

test('env precedence is workflow, job, step', (t) => {
  const w = ok(
    [
      'version: 1',
      'env: {A: w, B: w, C: w}',
      'jobs:',
      '  j:',
      '    env: {B: j, C: j}',
      '    steps:',
      '      - run: x',
      '        env: {C: s}'
    ].join('\n')
  )
  // The schema keeps the three scopes separate; the runner merges them narrowest-wins.
  t.alike(w.env, { A: 'w', B: 'w', C: 'w' })
  t.alike(w.jobs.j.env, { B: 'j', C: 'j' })
  t.alike(w.jobs.j.steps[0].env, { C: 's' })
})

test('jobs form, with needs resolved', (t) => {
  const w = ok(
    [
      'version: 1',
      'jobs:',
      '  lint:',
      '    steps: [npm run lint]',
      '  test:',
      '    needs: lint',
      '    steps: [npm test]'
    ].join('\n')
  )
  t.alike(Object.keys(w.jobs).sort(), ['lint', 'test'])
  t.alike(w.jobs.test.needs, ['lint'], 'a scalar needs is normalized to a list')
  t.absent(w.desugared)
})

// --- rejections ------------------------------------------------------------------------

test('version is required and pinned', (t) => {
  rejects(t, 'steps:\n  - echo\n', /version.*required/, 'missing version')
  rejects(t, 'version: 99\nsteps:\n  - echo\n', /unsupported schema version/, 'future version')
  rejects(t, 'version: "1"\nsteps:\n  - echo\n', /unsupported schema version/, 'stringly version')
})

test('unknown keys are rejected with a suggestion', (t) => {
  rejects(
    t,
    'version: 1\njobs:\n  a:\n    stpes: []\n',
    /did you mean "steps"/,
    'typo in a job key'
  )
  rejects(t, 'version: 1\nstpes: []\n', /did you mean "steps"/, 'typo at the top level')
  rejects(
    t,
    'version: 1\nsteps:\n  - run: x\n    tmeout: 5s\n',
    /did you mean "timeout"/,
    'typo in a step key'
  )
  rejects(
    t,
    'version: 1\nsteps:\n  - echo\nwibble: 1\n',
    /unknown key "wibble"/,
    'unknown key with no near match'
  )
})

test('unknown targets are rejected with a suggestion', (t) => {
  rejects(
    t,
    'version: 1\ntargets: [darwin-arm46]\nsteps: [x]\n',
    /did you mean "darwin-arm64"/,
    'target typo'
  )
  rejects(
    t,
    'version: 1\ntargets: [freebsd-x64]\nsteps: [x]\n',
    /unknown target/,
    'unsupported platform'
  )
  rejects(t, 'version: 1\ntargets: [host, host]\nsteps: [x]\n', /duplicate target/, 'duplicate')
  rejects(t, 'version: 1\ntargets: []\nsteps: [x]\n', /at least one target/, 'empty list')
})

test('steps must be a non-empty list of runnable things', (t) => {
  rejects(t, 'version: 1\nsteps: []\n', /at least one step/, 'empty steps')
  rejects(t, 'version: 1\nsteps: echo hi\n', /must be a list/, 'scalar steps')
  rejects(t, 'version: 1\nsteps:\n  - name: nothing\n', /needs a `run:`/, 'step with no run')
  rejects(t, 'version: 1\nsteps:\n  - run: "  "\n', /non-empty command/, 'blank run')
  rejects(t, 'version: 1\nsteps:\n  - ""\n', /empty/, 'blank shorthand')
  rejects(t, 'version: 1\nsteps:\n  - [a, b]\n', /command string or a mapping/, 'list step')
})

test('bad durations are rejected rather than coerced', (t) => {
  rejects(
    t,
    'version: 1\nsteps:\n  - run: x\n    timeout: 20 minutes\n',
    /500ms, 30s, 20m or 1h/,
    'prose duration'
  )
  rejects(t, 'version: 1\nsteps:\n  - run: x\n    timeout: 0s\n', /positive duration/, 'zero')
  rejects(t, 'version: 1\nsteps:\n  - run: x\n    timeout: -5\n', /positive duration/, 'negative')
})

test('needs must resolve, and cannot self-reference', (t) => {
  rejects(
    t,
    'version: 1\njobs:\n  a:\n    steps: [x]\n  b:\n    needs: [aa]\n    steps: [y]\n',
    /did you mean "a"/,
    'dangling need'
  )
  rejects(
    t,
    'version: 1\njobs:\n  a:\n    needs: [a]\n    steps: [x]\n',
    /cannot need itself/,
    'self need'
  )
})

test('duplicate step ids are rejected', (t) => {
  rejects(
    t,
    'version: 1\nsteps:\n  - {id: a, run: x}\n  - {id: a, run: y}\n',
    /duplicate step id/,
    'dup id'
  )
})

test('steps and jobs are mutually exclusive', (t) => {
  rejects(t, 'version: 1\nsteps: [x]\njobs:\n  a:\n    steps: [y]\n', /not both/, 'both forms')
  rejects(t, 'version: 1\nname: x\n', /jobs.*required/, 'neither form')
  rejects(t, 'version: 1\njobs: {}\n', /at least one job/, 'empty jobs')
})

test('YAML problems are reported with a position', (t) => {
  rejects(
    t,
    'version: 1\njobs:\n  build:\n   steps:\n  - bad\n',
    /line \d+, column \d+/,
    'syntax error'
  )
  // js-yaml 5 makes a duplicate key an error rather than a silent overwrite -- worth pinning,
  // because js-yaml 4 silently keeps the last one.
  rejects(t, 'version: 1\njobs:\n  a: 1\n  a: 2\n', /duplicat/i, 'duplicate mapping key')
  // And code execution via tags is refused outright.
  rejects(
    t,
    'version: 1\nsteps: !!js/function "function(){return 1}"\n',
    /unknown tag|function/i,
    'js/function tag'
  )
})

test('empty and content-free files say so plainly', (t) => {
  rejects(t, '', /file is empty/, 'empty')
  rejects(t, '   \n\n', /file is empty/, 'whitespace only')
  rejects(t, '# only a comment\n', /no workflow in it/, 'comment only')
})

test('the parsed workflow is frozen', (t) => {
  // The engine passes this object around freely; accidental mutation would be a very confusing bug.
  const w = ok('version: 1\nsteps:\n  - echo hi\n')
  t.ok(Object.isFrozen(w))
  t.ok(Object.isFrozen(w.jobs))
  t.ok(Object.isFrozen(w.jobs.main))
  t.ok(Object.isFrozen(w.jobs.main.steps))
  t.ok(Object.isFrozen(w.jobs.main.steps[0]))
})
