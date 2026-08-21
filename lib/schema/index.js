'use strict'

// Workflow parsing: YAML -> validated, normalized, frozen Workflow.
//
// This is the ONLY place in the codebase that touches YAML. That is deliberate containment: the
// intent is to replace js-yaml with our own parser, and confining it here makes that a single swap
// with no reach into the engine. Everything downstream sees a normalized object, never raw YAML.
//
// Error quality is a feature, not politeness. GHA's habit of accepting a typo and then silently
// doing nothing is the single largest source of mystery CI failures, so every diagnostic here names
// the YAML path (`jobs.build.steps[2].run`) and, where we can find it, the line.
//
// The schema is NOT GitHub Actions. There is no `uses:`, no remote action fetching, no expression
// language. See docs in the README for the reasoning.

const YAML = require('js-yaml')

const WorkflowError = require('../errors.js')
const targets = require('../targets.js')
const toolchains = require('../toolchains.js')
const publish = require('../publish')

// Bumping this is how semantics change without heuristics. Cheap now, impossible to retrofit.
const SCHEMA_VERSION = 1

const WORKFLOW_KEYS = [
  'version',
  'name',
  'env',
  'targets',
  'toolchain',
  'tier',
  'source',
  'expect',
  'jobs',
  'steps'
]
const JOB_KEYS = [
  'name',
  'targets',
  'toolchain',
  'env',
  'needs',
  'steps',
  'outputs',
  'artifacts',
  'prefetch',
  'source',
  'tier',
  'publish'
]

// A publish job is the trusted half of a run, so its shape is a whitelist rather than a blacklist:
// these keys and nothing else. Every rejected key is one that would either put user code beside the
// key (`steps`, `prefetch`) or configure a sandbox that does not exist (`toolchain`, `tier`).
const PUBLISH_JOB_KEYS = ['name', 'needs', 'publish']
const PUBLISH_KEYS = ['driver', 'artifact', 'name', 'key', 'dry-run']
const STEP_KEYS = ['name', 'id', 'run', 'shell', 'cwd', 'env', 'timeout', 'continue-on-error', 'if']

const DEFAULT_JOB = 'main'
const DEFAULT_SHELL = 'bash'

// --- diagnostics -----------------------------------------------------------------------

function fail(path, message, source) {
  const where = path ? `${path}: ` : ''
  const line = source ? findLine(source, path) : null
  const at = line ? ` (line ${line})` : ''
  throw WorkflowError.SCHEMA_INVALID(`${where}${message}${at}`)
}

// Best-effort line lookup for a normalized path. js-yaml gives positions for SYNTAX errors but not
// semantic ones, so we walk the raw text for the path's key segments in order. Approximate on
// purpose: a slightly wrong line is far more useful than no line, and it is never used for control
// flow -- only for the message.
function findLine(source, path) {
  if (!path) return null
  const keys = path
    .split('.')
    .map((seg) => seg.replace(/\[\d+\]$/, ''))
    .filter(Boolean)
  const lines = source.split('\n')
  let from = 0
  let found = null
  for (const key of keys) {
    const re = new RegExp(`^\\s*(-\\s*)?["']?${key}["']?\\s*:`)
    let hit = -1
    for (let i = from; i < lines.length; i++) {
      if (re.test(lines[i])) {
        hit = i
        break
      }
    }
    if (hit === -1) break
    found = hit + 1
    from = hit + 1
  }
  return found
}

function unknownKeys(obj, allowed, path, source) {
  for (const key of Object.keys(obj)) {
    if (allowed.includes(key)) continue
    const near = closest(key, allowed)
    fail(
      path ? `${path}.${key}` : key,
      `unknown key ${JSON.stringify(key)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}`,
      source
    )
  }
}

// Cheap edit-distance suggestion. `stpes:` should say "did you mean steps?" rather than leaving
// someone to diff against the docs.
function closest(word, candidates) {
  let best = null
  let bestScore = Infinity
  for (const c of candidates) {
    const d = distance(word, c)
    if (d < bestScore) {
      bestScore = d
      best = c
    }
  }
  return bestScore <= Math.max(2, Math.floor(word.length / 3)) ? best : null
}

function distance(a, b) {
  const rows = []
  for (let i = 0; i <= a.length; i++) rows.push([i])
  for (let j = 1; j <= b.length; j++) rows[0][j] = j
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      )
    }
  }
  return rows[a.length][b.length]
}

// --- primitives ------------------------------------------------------------------------

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
}

function asStringMap(value, path, source) {
  if (value === undefined || value === null) return {}
  if (!isPlainObject(value)) fail(path, `must be a mapping, got ${typeName(value)}`, source)
  const out = {}
  for (const key of Object.keys(value)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      fail(`${path}.${key}`, 'env names must be valid identifiers', source)
    }
    const v = value[key]
    if (v === null || typeof v === 'object') {
      fail(`${path}.${key}`, `must be a string, number or boolean, got ${typeName(v)}`, source)
    }
    // Numbers and booleans are quietly stringified: YAML will happily give you `1` for a version
    // and every consumer of an env var wants a string anyway.
    out[key] = String(v)
  }
  return out
}

function typeName(v) {
  if (v === null) return 'null'
  if (Array.isArray(v)) return 'a list'
  if (typeof v === 'object') return 'a mapping'
  return 'a ' + typeof v
}

// Durations are written the way humans write them (`30s`, `20m`, `1h`) and normalized to ms.
function asDurationMs(value, path, source) {
  if (value === undefined || value === null) return 0
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value <= 0) {
      fail(path, `must be a positive duration, got ${value}`, source)
    }
    return Math.round(value * 1000) // bare numbers are seconds
  }
  if (typeof value !== 'string') {
    fail(path, `must be a duration string, got ${typeName(value)}`, source)
  }
  const m = /^(\d+(?:\.\d+)?)(ms|s|m|h)$/.exec(value.trim())
  if (!m) fail(path, `must look like 500ms, 30s, 20m or 1h, got ${JSON.stringify(value)}`, source)
  const n = Number(m[1])
  const unit = { ms: 1, s: 1000, m: 60000, h: 3600000 }[m[2]]
  if (n <= 0) fail(path, `must be a positive duration, got ${JSON.stringify(value)}`, source)
  return Math.round(n * unit)
}

function asTargetList(value, path, source, dflt) {
  if (value === undefined || value === null) return dflt
  const list = Array.isArray(value) ? value : [value]
  if (list.length === 0) fail(path, 'must list at least one target', source)
  const out = []
  for (let i = 0; i < list.length; i++) {
    const t = list[i]
    if (typeof t !== 'string') {
      fail(`${path}[${i}]`, `must be a target string, got ${typeName(t)}`, source)
    }
    if (!targets.isTarget(t)) {
      const near = closest(t, targets.ALL)
      fail(
        `${path}[${i}]`,
        `unknown target ${JSON.stringify(t)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}`,
        source
      )
    }
    if (out.includes(t)) fail(`${path}[${i}]`, `duplicate target ${JSON.stringify(t)}`, source)
    out.push(t)
  }
  return out
}

// --- steps -----------------------------------------------------------------------------

function normalizeStep(raw, path, source, index) {
  // The shorthand: `- npm ci` is the 90% case and must stay one line. It normalizes to exactly the
  // same shape as the mapping form -- if it did not, every consumer would have to handle two shapes
  // and `step.shell` would be undefined half the time.
  if (typeof raw === 'string') {
    if (raw.trim().length === 0) fail(path, 'step command is empty', source)
    raw = { run: raw }
  }
  if (!isPlainObject(raw)) {
    fail(path, `must be a command string or a mapping, got ${typeName(raw)}`, source)
  }

  unknownKeys(raw, STEP_KEYS, path, source)

  if (raw.run === undefined) fail(path, 'step needs a `run:`', source)
  if (typeof raw.run !== 'string' || raw.run.trim().length === 0) {
    fail(`${path}.run`, `must be a non-empty command string, got ${typeName(raw.run)}`, source)
  }
  if (raw.id !== undefined && !/^[A-Za-z_][A-Za-z0-9_-]*$/.test(String(raw.id))) {
    fail(`${path}.id`, `must be an identifier, got ${JSON.stringify(raw.id)}`, source)
  }
  if (raw.shell !== undefined && typeof raw.shell !== 'string') {
    fail(`${path}.shell`, `must be a string, got ${typeName(raw.shell)}`, source)
  }
  if (raw.cwd !== undefined && typeof raw.cwd !== 'string') {
    fail(`${path}.cwd`, `must be a string, got ${typeName(raw.cwd)}`, source)
  }
  if (raw['continue-on-error'] !== undefined && typeof raw['continue-on-error'] !== 'boolean') {
    fail(
      `${path}.continue-on-error`,
      `must be true or false, got ${typeName(raw['continue-on-error'])}`,
      source
    )
  }
  if (raw.if !== undefined && typeof raw.if !== 'string') {
    fail(`${path}.if`, `must be a condition string, got ${typeName(raw.if)}`, source)
  }

  return freezeStep({
    index,
    id: raw.id === undefined ? null : String(raw.id),
    name: raw.name === undefined ? null : String(raw.name),
    run: raw.run,
    shell: raw.shell || DEFAULT_SHELL,
    cwd: raw.cwd || null,
    env: asStringMap(raw.env, `${path}.env`, source),
    timeoutMs: asDurationMs(raw.timeout, `${path}.timeout`, source),
    continueOnError: raw['continue-on-error'] === true,
    // Parsed and carried, but not evaluated until the conditional evaluator lands. Validating it
    // now means a workflow written today does not become invalid later.
    if: raw.if === undefined ? null : raw.if
  })
}

function freezeStep(step) {
  if (!step.name) step.name = firstLine(step.run)
  if (step.id === undefined) step.id = null
  return Object.freeze(step)
}

function firstLine(run) {
  const line = String(run).trim().split('\n')[0].trim()
  return line.length > 60 ? line.slice(0, 57) + '...' : line
}

function normalizeSteps(raw, path, source) {
  if (raw === undefined) fail(path, 'is required', source)
  if (!Array.isArray(raw)) fail(path, `must be a list of steps, got ${typeName(raw)}`, source)
  if (raw.length === 0) fail(path, 'must contain at least one step', source)

  const steps = raw.map((s, i) => normalizeStep(s, `${path}[${i}]`, source, i))

  const seen = new Set()
  for (const step of steps) {
    if (!step.id) continue
    if (seen.has(step.id)) {
      fail(`${path}[${step.index}].id`, `duplicate step id ${JSON.stringify(step.id)}`, source)
    }
    seen.add(step.id)
  }
  return Object.freeze(steps)
}

// --- jobs ------------------------------------------------------------------------------

// Artifacts are declared on BOTH sides -- what a job produces and what it consumes -- so the data
// flow between jobs is visible in the file before anything runs. That is what will let a farm peer
// prefetch a task's inputs before it is dispatched; GHA's upload/download-artifact actions hide the
// same graph inside step bodies and so cannot schedule around it.
function normalizeArtifacts(raw, path, source) {
  if (raw === undefined) return Object.freeze({ out: Object.freeze([]), in: Object.freeze([]) })
  if (!isPlainObject(raw)) {
    fail(path, `must be a mapping with \`out:\` and/or \`in:\`, got ${typeName(raw)}`, source)
  }
  unknownKeys(raw, ['out', 'in'], path, source)

  const out = []
  if (raw.out !== undefined) {
    if (!Array.isArray(raw.out)) {
      fail(`${path}.out`, `must be a list, got ${typeName(raw.out)}`, source)
    }
    raw.out.forEach((entry, i) => {
      const at = `${path}.out[${i}]`
      if (!isPlainObject(entry)) {
        fail(at, `must be a mapping with name: and path:, got ${typeName(entry)}`, source)
      }
      unknownKeys(entry, ['name', 'path', 'if-no-files-found'], at, source)
      if (typeof entry.name !== 'string' || !entry.name) fail(`${at}.name`, 'is required', source)
      if (typeof entry.path !== 'string' || !entry.path) fail(`${at}.path`, 'is required', source)
      const missing =
        entry['if-no-files-found'] === undefined ? 'warn' : String(entry['if-no-files-found'])
      if (!['error', 'warn', 'ignore'].includes(missing)) {
        fail(
          `${at}.if-no-files-found`,
          `must be error, warn or ignore, got ${JSON.stringify(missing)}`,
          source
        )
      }
      out.push(Object.freeze({ name: entry.name, path: entry.path, ifNoFilesFound: missing }))
    })
  }

  const inputs = []
  if (raw.in !== undefined) {
    if (!Array.isArray(raw.in)) {
      fail(`${path}.in`, `must be a list, got ${typeName(raw.in)}`, source)
    }
    raw.in.forEach((entry, i) => {
      const at = `${path}.in[${i}]`
      if (!isPlainObject(entry)) {
        fail(at, `must be a mapping with name: and to:, got ${typeName(entry)}`, source)
      }
      unknownKeys(entry, ['name', 'to'], at, source)
      if (typeof entry.name !== 'string' || !entry.name) fail(`${at}.name`, 'is required', source)
      const to = entry.to === undefined ? '.' : String(entry.to)
      if (to.startsWith('/') || to.split('/').includes('..')) {
        // A destination is always inside the workspace: an absolute or climbing path would be a way
        // to write outside it.
        fail(
          `${at}.to`,
          `must be a relative path inside the workspace, got ${JSON.stringify(to)}`,
          source
        )
      }
      inputs.push(Object.freeze({ name: entry.name, to }))
    })
  }

  return Object.freeze({ out: Object.freeze(out), in: Object.freeze(inputs) })
}

// What to prefetch on the HOST before the sandbox starts.
//
// This is what makes `network: none` a real default rather than an aspiration: a build cannot run
// `npm install` with no network, so the runner fetches from the committed lockfile first and hands
// the result in as a read-only cache. Declared per job rather than inferred, because "did this
// build reach the network" should be answerable by reading the file.
// `npm` fetches runtime dependencies; `npm-dev` adds devDependencies. Two explicit names rather
// than a nested option, because the choice matters (see lib/prefetch.js) and a name is easier to
// read in a diff than a flag.
const PREFETCHERS = ['npm', 'npm-dev']

function normalizePrefetch(raw, path, source) {
  if (raw === undefined) return Object.freeze([])
  const list = Array.isArray(raw) ? raw : [raw]
  const out = []
  list.forEach((entry, i) => {
    if (typeof entry !== 'string') {
      fail(`${path}[${i}]`, `must be a name, got ${typeName(entry)}`, source)
    }
    if (!PREFETCHERS.includes(entry)) {
      const near = closest(entry, PREFETCHERS)
      fail(
        `${path}[${i}]`,
        `unknown prefetcher ${JSON.stringify(entry)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}; known: ${PREFETCHERS.join(', ')}`,
        source
      )
    }
    if (!out.includes(entry)) out.push(entry)
  })
  return Object.freeze(out)
}

// The project directory to stream into the sandbox. `false` means "start from an empty workspace",
// which is what the small examples want.
function normalizeSource(raw, path, source, dflt) {
  if (raw === undefined) return dflt
  if (raw === false || raw === null) return null
  if (typeof raw !== 'string') fail(path, `must be a path or false, got ${typeName(raw)}`, source)
  if (raw.startsWith('/')) fail(path, 'must be relative to the workflow file', source)
  return raw
}

// Facts about the project that must hold before anything runs.
//
// `upgrade` exists because `bin.mjs` does `import pkg from './package.json'` -- the OTA link is
// COMPILED INTO the binary, so a distributable is only publishable against the link it was built
// with. The docs' own walkthrough has you switch the link and then rebuild for exactly this reason.
//
// We assert and never write. The runner stays a build tool rather than something that edits the
// developer's source, and the attestation keeps describing exactly what was in the tree. The cost is
// that forgetting to set the link is a failed run rather than a fixed one, so the message has to
// name the field and both links.
function normalizeExpect(raw, path, source) {
  if (raw === undefined) return Object.freeze({ upgrade: null })
  if (!isPlainObject(raw)) fail(path, `must be a mapping, got ${typeName(raw)}`, source)
  unknownKeys(raw, ['upgrade'], path, source)

  let upgrade = null
  if (raw.upgrade !== undefined) {
    if (typeof raw.upgrade !== 'string') {
      fail(`${path}.upgrade`, `must be a pear:// link, got ${typeName(raw.upgrade)}`, source)
    }
    if (!/^pear:\/\/[a-z0-9.]+$/i.test(raw.upgrade)) {
      fail(
        `${path}.upgrade`,
        `must look like pear://<key>, got ${JSON.stringify(raw.upgrade)}`,
        source
      )
    }
    upgrade = raw.upgrade
  }
  return Object.freeze({ upgrade })
}

// The minimum isolation tier a job requires.
//
// This is STATIC -- never interpolated -- for the same reason the rest of the sandbox posture is:
// what a job is allowed to run under must be knowable before any of its code executes, so that
// `plan --json` is a complete contract and nothing a build produces can widen its own sandbox.
//
// A workflow declaring `tier: microvm` means the runner refuses on a host that can only offer a
// shared kernel, rather than quietly running it anyway.
const TIERS = ['microvm', 'container']

function normalizeTier(raw, path, source, dflt) {
  if (raw === undefined) return dflt
  if (typeof raw !== 'string') fail(path, `must be a tier name, got ${typeName(raw)}`, source)
  if (!TIERS.includes(raw)) {
    const near = closest(raw, TIERS)
    fail(
      path,
      `unknown tier ${JSON.stringify(raw)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}; known: ${TIERS.join(', ')}`,
      source
    )
  }
  return raw
}

// A typo here should be caught at parse time, not as `npm: command not found` twenty seconds into
// a sandboxed step.
function normalizeToolchain(raw, path, source, dflt) {
  if (raw === undefined) return dflt
  if (typeof raw !== 'string') fail(path, `must be a toolchain name, got ${typeName(raw)}`, source)
  try {
    return toolchains.resolve(raw).name
  } catch (err) {
    fail(path, err.message.replace(/^UNKNOWN_TOOLCHAIN: /, ''), source)
  }
}

// Nothing inside `publish:` is interpolatable, for the same reason nothing inside `sandbox:` is:
// what a run is about to publish, and under which identity, must be fully known before any
// untrusted code has executed. A build that could rewrite its own publish target could redirect a
// release, which is a strictly worse outcome than any artifact it could forge.
function noInterpolation(value, path, source) {
  if (typeof value === 'string' && value.includes('{{')) {
    fail(
      path,
      'cannot be interpolated -- a publish target must be fully known before any build runs, ' +
        'so that a compromised job cannot redirect its own release',
      source
    )
  }
  return value
}

function normalizePublish(raw, path, source) {
  if (!isPlainObject(raw)) fail(path, `must be a mapping, got ${typeName(raw)}`, source)
  unknownKeys(raw, PUBLISH_KEYS, path, source)

  const driver = raw.driver
  if (driver === undefined) fail(`${path}.driver`, 'is required', source)
  if (typeof driver !== 'string') {
    fail(`${path}.driver`, `must be a driver name, got ${typeName(driver)}`, source)
  }
  if (!publish.resolve(driver)) {
    const near = closest(driver, publish.names())
    fail(
      `${path}.driver`,
      `unknown publish driver ${JSON.stringify(driver)}` +
        `${near ? `; did you mean ${JSON.stringify(near)}?` : ''}; known: ${publish.names().join(', ')}`,
      source
    )
  }

  for (const required of ['artifact', 'name', 'key']) {
    if (raw[required] === undefined) fail(`${path}.${required}`, 'is required', source)
    if (typeof raw[required] !== 'string') {
      fail(`${path}.${required}`, `must be a string, got ${typeName(raw[required])}`, source)
    }
    noInterpolation(raw[required], `${path}.${required}`, source)
  }

  // `key` is a NAME resolved against runner-side configuration, never the secret itself. Catching
  // an inlined key here is the difference between a refused workflow and a private key committed
  // to a repository, so the check is on the shape of the value rather than on the author's care.
  if (/^[0-9a-fA-F]{32,}$/.test(raw.key)) {
    fail(
      `${path}.key`,
      "looks like a key, not a key NAME. This field names an entry in the runner's own config; " +
        'secrets must never appear in a workflow file, which is why the field will not accept one',
      source
    )
  }
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(raw.key)) {
    fail(
      `${path}.key`,
      'must be a lowercase config name: letters, digits, dot, dash, underscore',
      source
    )
  }
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(raw.name)) {
    fail(`${path}.name`, 'must be a lowercase drive namespace name', source)
  }

  const dryRun = raw['dry-run']
  if (dryRun !== undefined && typeof dryRun !== 'boolean') {
    fail(`${path}.dry-run`, `must be true or false, got ${typeName(dryRun)}`, source)
  }

  return Object.freeze({
    driver,
    artifact: raw.artifact,
    name: raw.name,
    // Default TRUE. Publishing is the one irreversible thing a run does, so the safe value is the
    // one you get by not thinking about it.
    dryRun: dryRun === undefined ? true : dryRun,
    key: raw.key
  })
}

// The rejections here are the security boundary stated as diagnostics. Each one exists because the
// alternative -- accepting the key and quietly ignoring it -- would put something next to a private
// key that has no business being there.
const PUBLISH_REJECTED = {
  steps:
    'a publish job runs no user code: it has no sandbox, and the runner holds the signing key ' +
    "while it runs. Put the build in its own job and publish that job's artifact",
  prefetch: 'a publish job installs nothing -- its only input is an artifact another job produced',
  source: 'a publish job has no workspace; it publishes an artifact, not a directory tree',
  toolchain: 'a publish job runs on the runner, not in an image',
  tier: 'a publish job is not sandboxed, so there is no isolation tier to require',
  targets: 'a publish job runs once, on the runner -- there is nothing to fan out',
  artifacts: 'name the artifact to publish with `publish.artifact:` instead',
  outputs: 'a publish job produces a link, recorded in the attestation rather than as an output',
  env: 'a publish job runs no commands, so an environment would have nothing to apply to'
}

function normalizePublishJob(id, raw, ctx) {
  const path = `jobs.${id}`
  for (const key of Object.keys(raw)) {
    if (PUBLISH_JOB_KEYS.includes(key)) continue
    const why = PUBLISH_REJECTED[key]
    fail(
      `${path}.${key}`,
      why ||
        `is not allowed in a publish job; a publish job takes only: ${PUBLISH_JOB_KEYS.join(', ')}`,
      ctx.source
    )
  }

  const needs = raw.needs === undefined ? [] : Array.isArray(raw.needs) ? raw.needs : [raw.needs]
  for (let i = 0; i < needs.length; i++) {
    if (typeof needs[i] !== 'string') {
      fail(`${path}.needs[${i}]`, `must be a job name, got ${typeName(needs[i])}`, ctx.source)
    }
  }
  // The artifact store is per-run, so the job that built what we are publishing has to be in this
  // run and has to have finished. Without `needs` the publish would race the build it depends on.
  if (needs.length === 0) {
    fail(
      `${path}.needs`,
      'is required on a publish job: the artifact it publishes must be produced earlier in this ' +
        'same run, so the job that produces it has to be named here',
      ctx.source
    )
  }

  return Object.freeze({
    id,
    name: raw.name === undefined ? id : String(raw.name),
    publish: normalizePublish(raw.publish, `${path}.publish`, ctx.source),
    // A publish job still has to look like a job to the scheduler, so it carries the same fields --
    // emptied out. That keeps the graph, the `--job` filter and the run journal from needing to
    // know this kind exists.
    outputs: Object.freeze({}),
    artifacts: normalizeArtifacts(undefined, `${path}.artifacts`, ctx.source),
    prefetch: Object.freeze([]),
    tier: null,
    source: null,
    targets: Object.freeze([targets.HOST]),
    toolchain: null,
    env: Object.freeze({}),
    needs: Object.freeze(needs),
    steps: Object.freeze([])
  })
}

function normalizeJob(id, raw, ctx) {
  const path = `jobs.${id}`
  if (!isPlainObject(raw)) fail(path, `must be a mapping, got ${typeName(raw)}`, ctx.source)

  // A publish job is a different kind of thing, so it is validated against its own key set rather
  // than being an ordinary job with extra fields. The error then names what is actually wrong --
  // "a publish job has nowhere to run steps" -- instead of complaining about an unknown key.
  if (raw.publish !== undefined) return normalizePublishJob(id, raw, ctx)

  unknownKeys(raw, JOB_KEYS, path, ctx.source)

  const needs = raw.needs === undefined ? [] : Array.isArray(raw.needs) ? raw.needs : [raw.needs]
  for (let i = 0; i < needs.length; i++) {
    if (typeof needs[i] !== 'string') {
      fail(`${path}.needs[${i}]`, `must be a job name, got ${typeName(needs[i])}`, ctx.source)
    }
  }

  // Job outputs are DECLARED, mapping a name to an interpolated value evaluated after the job's
  // steps. Declaring them beats implicitly unioning every step's outputs: the data flow between jobs
  // is then visible in the file rather than being an emergent property of what the scripts happened
  // to write.
  const outputs = {}
  if (raw.outputs !== undefined) {
    if (!isPlainObject(raw.outputs)) {
      fail(
        `${path}.outputs`,
        `must be a mapping of name to value, got ${typeName(raw.outputs)}`,
        ctx.source
      )
    }
    for (const key of Object.keys(raw.outputs)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
        fail(`${path}.outputs.${key}`, 'output names must be valid identifiers', ctx.source)
      }
      const v = raw.outputs[key]
      if (v === null || typeof v === 'object') {
        fail(`${path}.outputs.${key}`, `must be a string, got ${typeName(v)}`, ctx.source)
      }
      outputs[key] = String(v)
    }
  }

  return Object.freeze({
    id,
    name: raw.name === undefined ? id : String(raw.name),
    outputs: Object.freeze(outputs),
    artifacts: normalizeArtifacts(raw.artifacts, `${path}.artifacts`, ctx.source),
    prefetch: normalizePrefetch(raw.prefetch, `${path}.prefetch`, ctx.source),
    tier: normalizeTier(raw.tier, `${path}.tier`, ctx.source, ctx.tier),
    source: normalizeSource(raw.source, `${path}.source`, ctx.source, ctx.sourceDir),
    targets: asTargetList(raw.targets, `${path}.targets`, ctx.source, ctx.targets),
    toolchain: normalizeToolchain(raw.toolchain, `${path}.toolchain`, ctx.source, ctx.toolchain),
    env: Object.freeze(asStringMap(raw.env, `${path}.env`, ctx.source)),
    needs: Object.freeze(needs),
    steps: normalizeSteps(raw.steps, `${path}.steps`, ctx.source)
  })
}

// --- entry -----------------------------------------------------------------------------

function parse(source, opts = {}) {
  if (typeof source !== 'string') {
    throw WorkflowError.SCHEMA_INVALID('workflow source must be a string')
  }

  // Handle this before js-yaml does: it throws "expected a document, but the input is empty", which
  // is accurate and unhelpful compared to naming the file.
  if (source.trim().length === 0) {
    throw WorkflowError.SCHEMA_INVALID(`${opts.filename || 'workflow'}: file is empty`)
  }

  let doc
  try {
    // js-yaml 5 is safe by default: `!!js/function` throws, and duplicate keys are an error with a
    // line:col rather than a silent overwrite. Both were open questions when this was planned.
    doc = YAML.load(source)
  } catch (err) {
    const reason = (err && err.reason) || (err && err.message) || String(err)
    // A comment-only file is "empty" as far as YAML is concerned; say that plainly rather than
    // reporting a parse failure for a file that looks fine to the author.
    if (/input is empty/i.test(reason)) {
      throw WorkflowError.SCHEMA_INVALID(
        `${opts.filename || 'workflow'}: file has no workflow in it`
      )
    }
    const at = err && err.mark ? ` (line ${err.mark.line + 1}, column ${err.mark.column + 1})` : ''
    throw WorkflowError.SCHEMA_SYNTAX(`${opts.filename || 'workflow'}: ${reason}${at}`)
  }

  if (doc === null || doc === undefined) {
    throw WorkflowError.SCHEMA_INVALID(`${opts.filename || 'workflow'}: file is empty`)
  }
  if (!isPlainObject(doc)) fail(null, `workflow must be a mapping, got ${typeName(doc)}`, source)

  unknownKeys(doc, WORKFLOW_KEYS, null, source)

  if (doc.version === undefined) {
    fail('version', `is required; add \`version: ${SCHEMA_VERSION}\``, source)
  }
  if (doc.version !== SCHEMA_VERSION) {
    throw WorkflowError.SCHEMA_VERSION(
      `version: unsupported schema version ${JSON.stringify(doc.version)}; this build understands ${SCHEMA_VERSION}`
    )
  }

  const hasTop = doc.steps !== undefined
  const hasJobs = doc.jobs !== undefined
  if (hasTop && hasJobs) {
    fail('steps', 'a workflow has either top-level `steps:` or `jobs:`, not both', source)
  }
  if (!hasTop && !hasJobs) fail('jobs', 'is required (or use top-level `steps:`)', source)

  const ctx = {
    source,
    targets: asTargetList(doc.targets, 'targets', source, Object.freeze([targets.HOST])),
    toolchain: normalizeToolchain(doc.toolchain, 'toolchain', source, null),
    // Default is an EMPTY workspace, not the project directory. Copying a repository into every
    // sandbox by default would be a surprising amount of IO for a workflow that does not need it,
    // and "what did this job have access to" should be declared rather than assumed.
    sourceDir: normalizeSource(doc.source, 'source', source, null),
    tier: normalizeTier(doc.tier, 'tier', source, null)
  }

  let jobs
  if (hasTop) {
    // Desugar: top-level `steps:` is one job named `main` inheriting the workflow's targets. It is
    // flattened here so the engine only ever deals with the full form -- but a six-line workflow
    // has to stay six lines, or the pitch versus GHA evaporates.
    jobs = Object.freeze({
      [DEFAULT_JOB]: Object.freeze({
        id: DEFAULT_JOB,
        name: DEFAULT_JOB,
        targets: ctx.targets,
        toolchain: ctx.toolchain,
        env: Object.freeze({}),
        needs: Object.freeze([]),
        outputs: Object.freeze({}),
        artifacts: normalizeArtifacts(undefined, 'artifacts', source),
        prefetch: Object.freeze([]),
        source: ctx.sourceDir,
        tier: ctx.tier,
        steps: normalizeSteps(doc.steps, 'steps', source)
      })
    })
  } else {
    if (!isPlainObject(doc.jobs)) {
      fail('jobs', `must be a mapping of job name to job, got ${typeName(doc.jobs)}`, source)
    }
    const ids = Object.keys(doc.jobs)
    if (ids.length === 0) fail('jobs', 'must define at least one job', source)

    const out = {}
    for (const id of ids) {
      if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(id)) {
        fail(`jobs.${id}`, `job name must be an identifier, got ${JSON.stringify(id)}`, source)
      }
      out[id] = normalizeJob(id, doc.jobs[id], ctx)
    }
    // `needs` must resolve. A dangling reference is otherwise a job that never runs, with no error.
    for (const id of ids) {
      for (const need of out[id].needs) {
        if (!out[need]) {
          const near = closest(need, ids)
          fail(
            `jobs.${id}.needs`,
            `references unknown job ${JSON.stringify(need)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}`,
            source
          )
        }
        if (need === id) fail(`jobs.${id}.needs`, 'a job cannot need itself', source)
      }
    }
    // A publish job's artifact must be produced upstream of it in THIS run -- the store is per-run,
    // so there is no earlier run to fall back on. Resolving the name here turns a typo into a parse
    // error instead of a run that builds everything, then fails at the last step with nothing to
    // publish. Note the closure is transitive: `stage` needing `assemble` needing `make` may publish
    // an artifact that `make` produced.
    for (const id of ids) {
      if (!out[id].publish) continue
      const wanted = out[id].publish.artifact
      const reachable = new Set()
      const stack = [...out[id].needs]
      while (stack.length) {
        const next = stack.pop()
        if (reachable.has(next) || !out[next]) continue
        reachable.add(next)
        stack.push(...out[next].needs)
      }
      const produced = new Set()
      for (const upstream of reachable) {
        for (const artifact of out[upstream].artifacts.out) {
          // A fanned-out name like `dist-{{ target }}` cannot be matched literally, so record the
          // template too and compare on its fixed prefix rather than claiming it is missing.
          produced.add(artifact.name)
        }
      }
      const matches = [...produced].some(
        (name) => name === wanted || (name.includes('{{') && wanted.startsWith(name.split('{{')[0]))
      )
      if (!matches) {
        const near = closest(
          wanted,
          [...produced].filter((n) => !n.includes('{{'))
        )
        fail(
          `jobs.${id}.publish.artifact`,
          `no job upstream of ${JSON.stringify(id)} produces an artifact named ` +
            `${JSON.stringify(wanted)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}` +
            `${produced.size ? `; reachable artifacts: ${[...produced].join(', ')}` : '; those jobs declare no artifacts at all'}`,
          source
        )
      }
    }
    jobs = Object.freeze(out)
  }

  return Object.freeze({
    version: doc.version,
    name: doc.name === undefined ? null : String(doc.name),
    source: ctx.sourceDir,
    env: Object.freeze(asStringMap(doc.env, 'env', source)),
    targets: ctx.targets,
    toolchain: ctx.toolchain,
    tier: ctx.tier,
    expect: normalizeExpect(doc.expect, 'expect', source),
    jobs,
    desugared: hasTop
  })
}

module.exports = {
  parse,
  PREFETCHERS,
  TIERS,
  SCHEMA_VERSION,
  DEFAULT_JOB,
  DEFAULT_SHELL,
  WORKFLOW_KEYS,
  JOB_KEYS,
  STEP_KEYS
}
