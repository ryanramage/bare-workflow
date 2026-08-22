'use strict'

// The attestation record: what actually ran, and what it produced.
//
// This exists because "the tier a build ran at" has to be a fact a consumer can check, not a claim
// the runner makes. Three things follow from that:
//
//   1. It records the ISOLATION POSTURE precisely -- tier, image digest, the sha256 of the seccomp
//      profile that was passed, and the full argv. Not "microvm", but the exact invocation, so a
//      weakening is visible after the fact and not just at review time.
//   2. It BINDS TO THE BYTES. Artifacts carry a content digest computed over the tree, so an
//      attestation cannot be paired with different output than the one it describes.
//   3. It is written for a FAILED task too. An attestation that only exists on success tells you
//      nothing about the run that went wrong, which is the one you want to inspect.
//
// This is also the record a farm peer would sign, and the reason the runner refuses to silently
// downgrade a tier: a downgrade would make every attestation after it a lie.

const fs = require('bare-fs')
const path = require('bare-path')
const crypto = require('bare-crypto')
const os = require('bare-os')
const targets = require('./targets.js')

const VERSION = 1

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex')
}

function fileSha256(file) {
  try {
    return sha256(fs.readFileSync(file))
  } catch {
    return null
  }
}

// A stable digest over a directory tree: sorted `sha256(content)  relative/path` lines, hashed.
//
// Sorted and relative on purpose -- the same tree produces the same digest regardless of readdir
// order or where it happens to be staged, which is what makes the digest comparable between a
// producer and a consumer on different machines.
function treeDigest(dir) {
  const entries = []
  const root = path.resolve(dir)

  const walk = (current, prefix) => {
    let names
    try {
      names = fs.readdirSync(current)
    } catch {
      return
    }
    names.sort()
    for (const name of names) {
      const abs = path.join(current, name)
      const rel = prefix ? prefix + '/' + name : name
      let stat
      try {
        stat = fs.lstatSync(abs)
      } catch {
        continue
      }
      if (stat.isSymbolicLink()) continue
      if (stat.isDirectory()) {
        walk(abs, rel)
        continue
      }
      if (!stat.isFile()) continue
      entries.push(`${fileSha256(abs)}  ${rel}`)
    }
  }
  walk(root, '')

  return {
    digest: 'sha256:' + sha256(Buffer.from(entries.join('\n'))),
    files: entries.length
  }
}

// Host facts worth pinning: a build that behaves differently later usually differs in one of these.
//
// `platform` and `execPlatform` are both recorded because they are not the same claim. On a Linux
// host they agree. On a Mac the host is darwin while the job ran inside a Linux guest, and for a
// consumer deciding whether to trust an artifact that is a material difference -- "built on macOS"
// would imply a signature that a Linux guest cannot have issued.
function hostFacts(versions = {}, tier = null) {
  return {
    platform: os.platform(),
    execPlatform: targets.executionPlatform(tier ? [tier] : [], os.platform()),
    arch: os.arch(),
    kernel: typeof os.version === 'function' ? os.version() : null,
    bare: typeof Bare !== 'undefined' && Bare.version ? Bare.version : null,
    ...versions
  }
}

// Best-effort source provenance. A dirty tree is recorded as such rather than omitted: "which
// commit" is much less useful than "which commit, plus whether it had uncommitted changes".
function sourceFacts(dir, run) {
  const out = { dir: dir || null, commit: null, dirty: null }
  if (!dir || typeof run !== 'function') return out
  const head = run('git', ['-C', dir, 'rev-parse', 'HEAD'])
  if (head) out.commit = head.trim()
  const status = run('git', ['-C', dir, 'status', '--porcelain'])
  if (status !== null) out.dirty = status.trim().length > 0
  return out
}

// Build the record for one task.
function forTask({
  run,
  task,
  job,
  result,
  isolation,
  source,
  prefetch,
  artifacts = [],
  versions
}) {
  return {
    version: VERSION,
    createdAt: new Date(run.now || Date.now()).toISOString(),
    run: {
      id: run.id,
      workflow: run.workflow || null,
      file: run.file || null
    },
    task: {
      id: task.id,
      job: job.id,
      target: task.target,
      toolchain: job.toolchain || null
    },
    status: result.status,
    isolation: {
      tier: isolation.tier,
      // Whether the boundary this tier names is SHARED between jobs. It is the whole caveat of the
      // `machine` tier: a podman-machine VM and a dedicated remote builder both report `machine`,
      // but they are not the same promise, and a farm deciding whether to trust an artifact needs to
      // know which one it got. null where the question does not apply.
      shared: isolation.shared === undefined ? null : isolation.shared,
      image: isolation.image || null,
      // The sha256 of the profile that was actually passed, not the path -- a path says nothing
      // about content, and the content is the control.
      seccomp: isolation.seccompProfile
        ? { path: isolation.seccompProfile, sha256: fileSha256(isolation.seccompProfile) }
        : null,
      program: isolation.program || null,
      argv: isolation.argv || null,
      agent: isolation.agent || null
    },
    host: hostFacts(versions, isolation.tier),
    source,
    inputs: {
      prefetch: prefetch || [],
      artifacts: (job.artifacts && job.artifacts.in ? job.artifacts.in : []).map((a) => a.name)
    },
    outputs: {
      artifacts,
      values: result.outputs || {}
    },
    steps: (result.steps || []).map((s) => ({
      index: s.index,
      name: s.name,
      outcome: s.outcome,
      conclusion: s.conclusion,
      code: s.code,
      ms: s.ms
    }))
  }
}

// A publish record. Deliberately a different shape from a task record rather than a task record with
// empty isolation fields: a publish has no tier, no image and no seccomp profile, and writing `null`
// into those would make an unsandboxed step look like a sandboxed one whose details went missing.
// What it records instead is the pair that answers "what is at this link": the artifact digest that
// went in, and the link and snapshot lengths that came out.
function forPublish({ run, task, job, result, artifact, publish, versions }) {
  return {
    version: VERSION,
    createdAt: new Date(run.now || Date.now()).toISOString(),
    run: { id: run.id, workflow: run.workflow || null, file: run.file || null },
    task: { id: task.id, job: job.id, target: task.target, toolchain: null },
    status: result.status,
    // Named so nothing mistakes this for a sandboxed record. `trusted` is the whole point: this ran
    // on the runner, with the key, by design.
    isolation: { tier: 'trusted', trusted: true, image: null, seccomp: null },
    host: hostFacts(versions, 'trusted'),
    inputs: {
      prefetch: [],
      artifacts: [artifact.name],
      // The digest is what makes the record mean something: it binds this link to the exact bytes a
      // sandboxed job produced, so "what is published here" is answerable without trusting a name.
      artifactDigest: artifact.digest || null,
      artifactFiles: artifact.files
    },
    publish: publish || null,
    outputs: { artifacts: [], values: {} },
    steps: []
  }
}

// Where a record lives. One file per task, plus a run-level summary -- so `attest <run-id>` can
// answer "what did this run do" without loading every task.
function pathFor(stateDir, runId, taskId) {
  const safe = String(taskId).replace(/[^A-Za-z0-9._-]/g, '-')
  return path.join(stateDir, 'runs', String(runId), safe + '.json')
}

function summaryPath(stateDir, runId) {
  return path.join(stateDir, 'runs', String(runId), 'run.json')
}

function write(stateDir, record) {
  const file = pathFor(stateDir, record.run.id, record.task.id)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const body = JSON.stringify(record, null, 2) + '\n'
  fs.writeFileSync(file, body)
  return { file, sha256: 'sha256:' + sha256(Buffer.from(body)) }
}

function writeSummary(stateDir, summary) {
  const file = summaryPath(stateDir, summary.run.id)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify(summary, null, 2) + '\n')
  return file
}

function read(stateDir, runId) {
  const dir = path.join(stateDir, 'runs', String(runId))
  let names
  try {
    names = fs.readdirSync(dir)
  } catch {
    return { summary: null, tasks: [] }
  }
  let summary = null
  const tasks = []
  for (const name of names.sort()) {
    if (!name.endsWith('.json')) continue
    let doc
    try {
      doc = JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'))
    } catch {
      continue
    }
    if (name === 'run.json') summary = doc
    else tasks.push(doc)
  }
  return { summary, tasks }
}

module.exports = {
  VERSION,
  forTask,
  forPublish,
  treeDigest,
  hostFacts,
  sourceFacts,
  write,
  writeSummary,
  read,
  pathFor,
  summaryPath,
  sha256,
  fileSha256
}
