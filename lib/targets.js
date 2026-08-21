'use strict'

// The target vocabulary.
//
// A target is a `<platform>-<arch>` string, and the set is CLOSED -- deliberately identical to
// pear-build's supported set, plus the pseudo-target `host`. A typo is therefore a schema error at
// parse time rather than a job that silently never gets scheduled.
//
// The load-bearing idea: a target is BOTH a build-matrix axis and a placement constraint. When the
// farm arrives, `satisfies()` stops being called with the local capability record and starts being
// called with an announced peer's -- and that is the whole routing decision. Designing it now is
// what keeps v2 from being a redesign, even though today there is only one peer.

const os = require('bare-os')
const WorkflowError = require('./errors.js')

// Exactly pear-build's flags (--darwin-arm64-app, --ios-arm64, ...), which is what a workflow will
// ultimately hand to `pear build`.
const TARGETS = [
  'linux-x64',
  'linux-arm64',
  'darwin-x64',
  'darwin-arm64',
  'win32-x64',
  'win32-arm64',
  'ios-arm64',
  'ios-arm64-simulator',
  'ios-x64-simulator',
  'android-arm64'
]

// "No placement constraint" -- runs wherever, for platform-agnostic work like linting.
const HOST = 'host'

const ALL = [HOST, ...TARGETS]

// Which targets a given platform can produce natively. Cross-compiling is possible in places
// (linux-arm64 from linux-x64 with a toolchain, darwin-arm64 from darwin-x64) but it is NOT assumed
// here: claiming a capability we cannot honour is worse than declining, because the job fails late
// and confusingly instead of being routed to a peer that can do it.
const NATIVE = {
  linux: ['linux-x64', 'linux-arm64'],
  darwin: ['darwin-x64', 'darwin-arm64', 'ios-arm64', 'ios-arm64-simulator', 'ios-x64-simulator'],
  win32: ['win32-x64', 'win32-arm64']
}

function parse(target) {
  if (typeof target !== 'string' || target.length === 0) {
    throw WorkflowError.UNKNOWN_TARGET(
      `target must be a non-empty string, got ${JSON.stringify(target)}`
    )
  }
  if (target === HOST) return { name: HOST, platform: null, arch: null, host: true }
  if (!TARGETS.includes(target)) {
    throw WorkflowError.UNKNOWN_TARGET(
      `unknown target ${JSON.stringify(target)}; known targets: ${ALL.join(', ')}`
    )
  }
  // Split on the FIRST dash: `ios-arm64-simulator` is platform `ios`, arch `arm64-simulator`.
  const i = target.indexOf('-')
  return { name: target, platform: target.slice(0, i), arch: target.slice(i + 1), host: false }
}

function isTarget(target) {
  return target === HOST || TARGETS.includes(target)
}

// The local capability record. This shape is also the future swarm announcement payload -- keeping
// them the same is the point.
function describe(opts = {}) {
  const platform = opts.platform || os.platform()
  const arch = opts.arch || os.arch()
  const native = NATIVE[platform] || []
  return {
    version: 1,
    platform,
    arch,
    // `host` first: every peer can run unconstrained work.
    targets: [HOST, ...native],
    tiers: opts.tiers || [],
    cpus: opts.cpus ?? (os.cpus ? os.cpus().length : 1)
  }
}

// Can these capabilities run this target? In v1 `caps` is always the local record; in the farm it
// is a peer's, and this same call becomes the routing decision.
function satisfies(caps, target) {
  const name = typeof target === 'string' ? target : target && target.name
  if (name === HOST) return true
  return !!caps && Array.isArray(caps.targets) && caps.targets.includes(name)
}

// Everything in `targets` that these capabilities cannot build. Reported as `unsupported` rather
// than silently mismapped -- wrkflw maps `macos-*` to `rust:latest`, which is worse than failing
// because you get a green build of the wrong thing.
function unsatisfied(caps, targets) {
  return (targets || []).filter((t) => !satisfies(caps, t))
}

module.exports = { TARGETS, HOST, ALL, NATIVE, parse, isTarget, describe, satisfies, unsatisfied }
