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

// What a host can actually produce.
//
// The naive model is "you can only build for your own platform". That is wrong, and measurably so:
// `bare-build` never invokes a compiler. It injects the JS bundle into a *prebuilt* Bare runtime
// using `bare-lief` -- an ELF `PT_LOAD` segment, a PE `.bare` section, a Mach-O `__BARE` segment --
// and those prebuilt runtimes are plain npm dependencies carrying no `os`/`cpu` fields, so every
// host has all of them. Cross-LINKING therefore works for every target from every host.
//
// What actually varies is whether the RESULT IS USABLE, and there is exactly one reason it might
// not be: **a code signature the host cannot produce.**
//
//   * An arm64 Mach-O must carry a valid signature or Apple Silicon SIGKILLs it. The prebuilt
//     darwin-arm64 runtime ships ad-hoc signed, injecting `__BARE` invalidates that signature, and
//     `bare-build`'s only re-signing path is `codesign` guarded by `os.platform() === 'darwin'`.
//     So a Linux-built darwin-arm64 binary is dead on arrival -- silently. Measured: our build came
//     out with 21 load commands and a now-stale LC_CODE_SIGNATURE.
//   * iOS binaries always require a signature, so the same constraint applies.
//   * win32-* and darwin-x64 run *unsigned* (SmartScreen / Gatekeeper friction, not failure), and
//     the darwin-x64 runtime ships with no signature to invalidate. Both cross-build fine.
//
// So the rule is per-TARGET, not per-platform: a target is buildable here unless it needs a
// signature that only another OS can issue.
const SIGNING_HOST = {
  'darwin-arm64': 'darwin',
  'ios-arm64': 'darwin',
  'ios-arm64-simulator': 'darwin',
  'ios-x64-simulator': 'darwin'
}

// Targets whose packaging tooling we have NOT verified cross-platform. Declared unbuildable rather
// than guessed at: `bare-apk` and friends ship prebuilds for only some hosts, and claiming a
// capability we cannot honour fails late and confusingly instead of routing to a peer that can.
const UNVERIFIED = ['android-arm64']

// Retained for reference: which targets each platform owns natively. No longer the capability rule.
const NATIVE = {
  linux: ['linux-x64', 'linux-arm64'],
  darwin: ['darwin-x64', 'darwin-arm64', 'ios-arm64', 'ios-arm64-simulator', 'ios-x64-simulator'],
  win32: ['win32-x64', 'win32-arm64']
}

// Can `platform` produce a usable `target`?
function buildableOn(platform, target) {
  if (target === HOST) return true
  if (UNVERIFIED.includes(target)) {
    return NATIVE[platform] ? NATIVE[platform].includes(target) : false
  }
  const needs = SIGNING_HOST[target]
  return needs === undefined || needs === platform
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
  const buildable = TARGETS.filter((t) => buildableOn(platform, t))
  return {
    version: 1,
    platform,
    arch,
    // `host` first: every peer can run unconstrained work.
    targets: [HOST, ...buildable],
    // Recorded separately so a farm can tell "I cannot build this" from "I cannot SIGN this" --
    // the second is what routing to a Mac peer actually solves.
    unsignable: TARGETS.filter((t) => !buildableOn(platform, t) && SIGNING_HOST[t]),
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

module.exports = {
  TARGETS,
  HOST,
  ALL,
  NATIVE,
  SIGNING_HOST,
  UNVERIFIED,
  parse,
  isTarget,
  buildableOn,
  describe,
  satisfies,
  unsatisfied
}
