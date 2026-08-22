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

// WHERE A JOB ACTUALLY EXECUTES, per tier -- which is not the same thing as the host platform, and
// conflating the two is a real bug rather than a tidiness issue.
//
// Every tier here runs the workload in a **Linux** container or microVM. On a Linux host that
// coincides with `os.platform()`, so the distinction never mattered and the code quietly used the
// host. On a Mac it diverges and the consequence is severe: `os.platform()` is 'darwin', so the
// signing rule below concludes darwin-arm64 is buildable -- while the job runs inside a Linux guest
// where `codesign` does not exist. The runner would then CLAIM the one capability a Mac is wanted
// for and produce exactly the dead-on-arrival binary this whole model exists to refuse.
//
// So capability is a function of the execution platform. A darwin-native or darwin-VM tier, when one
// exists, is what maps to 'darwin' -- and that is precisely why such a tier is the thing that
// unlocks darwin-arm64, not the host merely being a Mac.
const TIER_PLATFORM = {
  container: 'linux',
  microvm: 'linux'
}

// Every tier this runner offers executes on the same platform. Derived rather than written down, so
// that adding a darwin tier to TIER_PLATFORM is what changes the answer here.
const TIER_PLATFORMS = [...new Set(Object.values(TIER_PLATFORM))]

// The platform jobs will run on, given the tiers in play.
//
// The empty case matters more than it looks. `validate` and `doctor` ask this when NO tier is
// available -- podman missing, or a stopped podman machine -- and falling back to the host is wrong
// on exactly one platform: a Mac would be told it can build darwin-arm64, when what it will
// actually get once configured is a Linux guest that cannot sign. So the fallback is "the platform
// this runner's tiers execute on", which is a property of the tier registry rather than of the host.
// On Linux the two answers coincide, which is why this was invisible.
function executionPlatform(tiers, host) {
  const named = (tiers || []).map((t) => (typeof t === 'string' ? t : t && t.name)).filter(Boolean)
  const platforms = new Set(named.map((t) => TIER_PLATFORM[t]).filter(Boolean))
  if (platforms.size === 1) return [...platforms][0]
  // A tier we do not recognise: that is a caller with its own execution platform (a native or VM
  // tier), so the host is the right answer.
  if (named.length && platforms.size === 0) return host
  // Nothing to go on. Answer with what this runner's tiers would give, not with the host.
  if (!named.length && TIER_PLATFORMS.length === 1) return TIER_PLATFORMS[0]
  return host
}

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
  const tiers = opts.tiers || []
  // Capability follows the EXECUTION platform, not the host. See TIER_PLATFORM above -- on a Mac
  // running Linux containers these differ, and using the host would claim darwin-arm64 while
  // building it somewhere `codesign` does not exist.
  const runsOn = opts.execPlatform || executionPlatform(tiers, platform)
  const buildable = TARGETS.filter((t) => buildableOn(runsOn, t))
  return {
    version: 1,
    platform,
    arch,
    // Both are recorded, because a farm peer announcing this needs to be able to say "I am a Mac,
    // but my jobs run in Linux" -- which is a genuinely different offer from "I build on macOS".
    execPlatform: runsOn,
    // `host` first: every peer can run unconstrained work.
    targets: [HOST, ...buildable],
    // Recorded separately so a farm can tell "I cannot build this" from "I cannot SIGN this" --
    // the second is what routing to a Mac peer actually solves.
    unsignable: TARGETS.filter((t) => !buildableOn(runsOn, t) && SIGNING_HOST[t]),
    tiers,
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
  TIER_PLATFORM,
  executionPlatform,
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
