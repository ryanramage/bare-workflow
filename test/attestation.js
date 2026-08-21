'use strict'

// Attestation tests.
//
// The record exists so that "the tier a build ran at" is a fact a consumer can check rather than a
// claim the runner makes. So the assertions worth having are: it binds to the actual BYTES, it
// records the isolation posture precisely enough to detect a weakening, and it exists even for a
// failed task -- the run you most want to inspect is the one that went wrong.

const test = require('brittle')
const fs = require('bare-fs')
const attestation = require('../lib/attestation.js')

let n = 0
function tmp(label) {
  const dir = `/tmp/bw-att-${label}-${Date.now()}-${n++}`
  fs.mkdirSync(dir, { recursive: true })
  return dir
}
const clean = (...dirs) => {
  for (const d of dirs) {
    try {
      fs.rmSync(d, { recursive: true, force: true })
    } catch {}
  }
}

const TASK = { id: 'build:linux-x64', target: 'linux-x64' }
const JOB = {
  id: 'build',
  toolchain: 'pear',
  artifacts: { in: [{ name: 'src' }], out: [] },
  prefetch: ['npm']
}
const RESULT = {
  status: 'success',
  outputs: { version: '1.2.3' },
  steps: [{ index: 0, name: 'make', outcome: 'success', conclusion: 'success', code: 0, ms: 42 }]
}

test('a tree digest is stable, content-sensitive and path-sensitive', (t) => {
  const dir = tmp('tree')
  try {
    fs.mkdirSync(dir + '/sub', { recursive: true })
    fs.writeFileSync(dir + '/a', 'alpha')
    fs.writeFileSync(dir + '/sub/b', 'beta')

    const first = attestation.treeDigest(dir)
    t.is(first.files, 2)
    t.ok(/^sha256:[0-9a-f]{64}$/.test(first.digest))
    // Stable, so producer and consumer on different machines compute the same value.
    t.is(attestation.treeDigest(dir).digest, first.digest, 'stable across calls')

    fs.writeFileSync(dir + '/sub/b', 'BETA')
    t.not(attestation.treeDigest(dir).digest, first.digest, 'changes when content changes')

    fs.writeFileSync(dir + '/sub/b', 'beta')
    t.is(attestation.treeDigest(dir).digest, first.digest, 'and changes back')

    // A rename is a different tree even with identical bytes -- the digest covers paths too.
    fs.renameSync(dir + '/sub/b', dir + '/sub/c')
    t.not(attestation.treeDigest(dir).digest, first.digest, 'path-sensitive')
  } finally {
    clean(dir)
  }
})

test('symlinks do not contribute to a digest', (t) => {
  // They are skipped on the way out of a sandbox, so counting them would make the digest describe
  // something the artifact does not contain.
  const dir = tmp('link')
  try {
    fs.writeFileSync(dir + '/real', 'x')
    const before = attestation.treeDigest(dir)
    fs.symlinkSync('/etc/hostname', dir + '/link')
    t.is(attestation.treeDigest(dir).digest, before.digest, 'unchanged by a symlink')
    t.is(attestation.treeDigest(dir).files, 1)
  } finally {
    clean(dir)
  }
})

test('the record pins the isolation posture, not just its name', (t) => {
  const profile = tmp('seccomp') + '/build-v1.json'
  fs.writeFileSync(profile, '{"defaultAction":"SCMP_ACT_ERRNO"}')
  try {
    const record = attestation.forTask({
      run: { id: 'r1', workflow: 'w', file: 'w.yml' },
      task: TASK,
      job: JOB,
      result: RESULT,
      isolation: {
        tier: 'microvm',
        image: 'localhost/x@sha256:' + 'a'.repeat(64),
        seccompProfile: profile,
        program: 'podman',
        argv: ['podman', 'run', '--network', 'none'],
        agent: 'bw-agent/1'
      },
      source: { dir: '/src', commit: 'abc', dirty: false }
    })

    t.is(record.isolation.tier, 'microvm')
    // The sha256 of the profile that was PASSED -- a path says nothing about content, and the
    // content is the actual control.
    t.ok(/^[0-9a-f]{64}$/.test(record.isolation.seccomp.sha256), 'seccomp content is hashed')
    t.is(record.isolation.seccomp.path, profile)
    t.alike(
      record.isolation.argv,
      ['podman', 'run', '--network', 'none'],
      'the exact argv, so a weakening is visible'
    )
    t.ok(record.isolation.image.includes('@sha256:'), 'image is digest-pinned')
    t.is(record.isolation.agent, 'bw-agent/1')
  } finally {
    clean(profile)
  }
})

test('the record captures task, host, source and step facts', (t) => {
  const record = attestation.forTask({
    run: { id: 'r1', workflow: 'w', file: 'w.yml' },
    task: TASK,
    job: JOB,
    result: RESULT,
    isolation: { tier: 'container' },
    source: { dir: '/src', commit: 'deadbeef', dirty: true },
    prefetch: ['npm'],
    artifacts: [{ name: 'app', files: 2, bytes: 10, digest: 'sha256:' + 'b'.repeat(64) }],
    versions: { podman: '6.1.0' }
  })

  t.is(record.version, attestation.VERSION)
  t.is(record.task.id, 'build:linux-x64')
  t.is(record.task.target, 'linux-x64')
  t.is(record.task.toolchain, 'pear', 'which toolchain, because that is which image')
  t.is(record.status, 'success')

  t.is(record.host.platform, 'linux')
  t.is(record.host.podman, '6.1.0')
  t.ok(record.host.bare, 'the runtime version is pinned too')

  // A dirty tree is recorded as such: "which commit" is much less useful than "which commit, and
  // whether it had uncommitted changes".
  t.is(record.source.commit, 'deadbeef')
  t.is(record.source.dirty, true)

  t.alike(record.inputs.prefetch, ['npm'])
  t.alike(record.inputs.artifacts, ['src'], 'declared inputs are recorded')
  t.is(record.outputs.artifacts[0].digest.length, 71, 'artifacts carry a content digest')
  t.alike(record.outputs.values, { version: '1.2.3' })
  t.is(record.steps.length, 1)
  t.is(record.steps[0].conclusion, 'success')
  t.ok(record.createdAt.endsWith('Z'), 'timestamped in UTC')
})

test('a failed task still gets a record', (t) => {
  // An attestation that only exists on success tells you nothing about the run you want to inspect.
  const record = attestation.forTask({
    run: { id: 'r1' },
    task: TASK,
    job: JOB,
    result: {
      status: 'failure',
      steps: [{ index: 0, name: 'make', outcome: 'failure', conclusion: 'failure', code: 2, ms: 5 }]
    },
    isolation: { tier: 'microvm' },
    source: { dir: null, commit: null, dirty: null }
  })
  t.is(record.status, 'failure')
  t.is(record.steps[0].code, 2)
  t.alike(record.outputs.artifacts, [], 'and publishes nothing')
})

test('records round-trip through disk, keyed by run and task', (t) => {
  const state = tmp('state')
  try {
    const record = attestation.forTask({
      run: { id: 'run-1', workflow: 'w' },
      task: TASK,
      job: JOB,
      result: RESULT,
      isolation: { tier: 'microvm' },
      source: { dir: null, commit: null, dirty: null }
    })
    const written = attestation.write(state, record)
    t.ok(fs.statSync(written.file).size > 0)
    // The record itself is hashed, so a stored attestation can be referenced by digest later.
    t.ok(/^sha256:[0-9a-f]{64}$/.test(written.sha256))

    attestation.writeSummary(state, {
      version: attestation.VERSION,
      run: { id: 'run-1', tier: 'microvm', minTier: 'microvm' },
      status: 'success',
      tasks: [{ id: TASK.id, status: 'success' }]
    })

    const back = attestation.read(state, 'run-1')
    t.is(back.tasks.length, 1)
    t.is(back.tasks[0].task.id, 'build:linux-x64')
    t.is(back.summary.run.tier, 'microvm')
    t.is(back.summary.run.minTier, 'microvm', 'what ran, and what was required')
  } finally {
    clean(state)
  }
})

test('reading a run that does not exist is empty, not an error', (t) => {
  const back = attestation.read('/tmp/definitely-not-a-state-dir', 'nope')
  t.is(back.summary, null)
  t.alike(back.tasks, [])
})

test('a task id with awkward characters still lands on a safe filename', (t) => {
  // Task ids contain a colon (`build:linux-x64`), which is not something to put in a path verbatim.
  const file = attestation.pathFor('/state', 'run-1', 'build:linux-x64')
  t.absent(file.includes(':'), 'colon replaced: ' + file)
  t.ok(file.endsWith('build-linux-x64.json'))
})
