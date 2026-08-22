'use strict'

// Tier detection and the refuse-to-run policy.
//
// The policy is the important part, not the probing: **if the best available tier is below the
// required minimum, we exit rather than run.** Three reasons, in order of weight:
//
//   1. Failure is asymmetric. Refusing costs a build that did not run. Degrading costs
//      ~/.ssh/id_ed25519, an npm token, a GitHub token -- and once signing exists, a signing
//      identity. A build farm is the highest-value target in the infrastructure it serves.
//   2. Silent degradation makes the attestation a lie. The farm needs artifacts to carry the tier
//      they were built at so a consumer can reject weakly-built binaries; a runner that quietly
//      downgrades destroys that.
//   3. It is the only thing that makes anyone install libkrun. A silent fallback guarantees the
//      strong tier is never exercised and rots.
//
// wrkflw does the opposite -- Docker unavailable means quietly running on the host -- and that is
// precisely the failure mode this exists to prevent.

const { spawnSync } = require('bare-subprocess')
const fs = require('bare-fs')
const os = require('bare-os')

const WorkflowError = require('./../errors.js')
const { hostEnv, which } = require('./../host-env.js')

// Ranked by what a full compromise of the workload actually buys an attacker, not by convenience.
const TIERS = [
  { name: 'microvm', rank: 90 },
  { name: 'container', rank: 50 }
]

const RANK = TIERS.reduce((acc, t) => ({ ...acc, [t.name]: t.rank }), {})

// NOTE ON TIMEOUTS: this used to pass `timeout: 30000` to spawnSync. `bare-subprocess` has no such
// option -- the word does not appear in the module -- so that guard was inert on every platform and
// had been since it was written. It is removed rather than left in place looking like protection.
// There is no way to bound a SYNCHRONOUS spawn from inside the process, and probe() is sync by
// design (see test/support/launchers.js). The remaining hang risk is podman's own ssh transport
// stalling against a booting machine; if that is ever observed it needs a watchdog subprocess, not
// an option that does nothing.
//
// The `which` guard below is not just tidiness. bare-subprocess throws ENOENT for a missing program
// AND the bare process then exits 144 during teardown even when the throw is caught -- measured. So
// spawning a binary that is known-absent poisons the exit code of the whole run.
function sh(file, args) {
  const found = which(file)
  if (found === null) {
    return { code: -1, stdout: '', stderr: `${file} not found`, missing: true }
  }
  try {
    const r = spawnSync(file, args, { env: hostEnv() })
    return {
      code: r.status === null ? -1 : r.status,
      stdout: r.stdout ? r.stdout.toString() : '',
      stderr: r.stderr ? r.stderr.toString() : '',
      missing: false
    }
  } catch (err) {
    return { code: -1, stdout: '', stderr: String(err), missing: false }
  }
}

// Why podman did not answer. The distinction is the whole point: "not installed" and "installed but
// its VM is not running" have completely different fixes, and reporting the second as the first is
// how a Mac user is told to install software they already have.
//
// On macOS and Windows podman is a remote client to a Linux VM, so a stopped machine is the NORMAL
// state of a working installation -- exit 125 with "Cannot connect to Podman".
function diagnosePodman(r) {
  if (r.missing) {
    return {
      reason: 'podman not found',
      remediation:
        os.platform() === 'darwin'
          ? 'brew install podman (or the pkg from podman.io), then: podman machine init'
          : 'install podman (rootless is fine)'
    }
  }
  const text = r.stdout + r.stderr
  if (
    /Cannot connect to Podman|unable to connect to Podman socket|connection refused/i.test(text)
  ) {
    return {
      reason: 'podman is installed but its service is not reachable',
      remediation:
        os.platform() === 'linux'
          ? 'start the podman service, or check: podman system connection list'
          : 'podman machine start (check: podman machine list)'
    }
  }
  const first = text.trim().split('\n')[0] || `podman exited ${r.code}`
  return {
    reason: `podman is installed but did not answer: ${first}`,
    remediation: 'check: podman system connection list'
  }
}

function exists(path) {
  try {
    fs.statSync(path)
    return true
  } catch {
    return false
  }
}

// The microvm verdict that follows from the platform alone, or null on Linux where it has to be
// probed for real.
//
// On a non-Linux host the old probes were meaningless: they looked for `.so` files under /usr/lib and
// for /dev/kvm, which on macOS resolve to paths that cannot exist and on Windows to C:\usr\lib. They
// reported "unavailable" for the right reason by accident, with remediation ("pacman -S libkrun
// libkrunfw", "enable KVM") that cannot be followed on the platform reading it. Since decision 4
// rests entirely on remediation being actionable, say the true thing instead.
//
// The deeper point: podman on macOS and Windows is a REMOTE client to a Linux VM, so the question is
// not what this host has but what the podman machine has -- and a stock machine image ships neither
// libkrun nor a +LIBKRUN crun. On Apple Silicon there is no path at all: applehv guests get no
// /dev/kvm, and nested virtualisation needs M3+ and is not exposed by podman machine.
function platformMicrovm(platform) {
  if (platform === 'linux') return null
  return {
    reason: `krun is Linux-only and this host is ${platform}`,
    remediation:
      'containers here already run inside a podman-machine VM, which is a host boundary but is ' +
      'SHARED between jobs; use --tier container knowing that, or see CLAUDE.md'
  }
}

// Probes are honest about WHY a tier is unavailable and how to fix it. "microvm unavailable" with no
// remediation is how a strong tier stays uninstalled forever.
function probe(opts = {}) {
  const image = opts.image || null
  const platform = opts.platform || os.platform()
  const results = []

  // Whether krun can EVER work here is a property of the platform, and it does not depend on podman
  // answering. Deciding it first matters: otherwise a stopped podman machine on a Mac hides the
  // permanent fact ("krun is Linux-only") behind a transient one ("the machine is not running"), and
  // the user fixes the transient one only to be told something that was never going to change.
  const microPlatform = platformMicrovm(platform)

  // `info`, not `version`: info reports SERVER-side facts, which is the question that actually
  // matters and the only one that distinguishes a stopped machine from a missing install. CLAUDE.md
  // calls for this explicitly so a stopped machine is diagnosed rather than guessed at.
  const podman = sh('podman', ['info', '--format', '{{.Version.Version}}'])
  if (podman.code !== 0) {
    const { reason, remediation } = diagnosePodman(podman)
    for (const tier of TIERS) {
      // microvm keeps its platform verdict even here -- see above.
      const permanent = tier.name === 'microvm' && microPlatform
      results.push({
        ...tier,
        available: false,
        reason: permanent ? microPlatform.reason : reason,
        remediation: permanent ? microPlatform.remediation : remediation
      })
    }
    results.sort((a, b) => b.rank - a.rank)
    return { tiers: results, podman: null }
  }

  const version = podman.stdout.trim()

  // container tier
  const containerReasons = []
  if (image) {
    const img = sh('podman', ['image', 'inspect', image, '--format', '{{.Digest}}'])
    if (img.code !== 0) containerReasons.push(`image ${image} not present`)
  }
  results.push({
    ...RANKED('container'),
    available: containerReasons.length === 0,
    reason: containerReasons.join('; ') || null,
    remediation: containerReasons.length ? 'bare scripts/build/agent.js' : null
  })

  // microvm tier: crun must be built +LIBKRUN, libkrun must be installed, and /dev/kvm writable.
  // crun selects the microVM path by ANNOTATION (run.oci.handler=krun), not --runtime krun.
  const microReasons = []
  const remediation = []

  // On a non-Linux host these probes are meaningless: they look for `.so` files under /usr/lib and
  // for /dev/kvm, which on macOS resolve to paths that cannot exist and on Windows to C:\usr\lib.
  // They would report "unavailable" for the right reason by accident, with remediation ("pacman -S
  // libkrun libkrunfw", "enable KVM") that cannot be followed on the platform reading it. Since
  // decision-making here rests on remediation being actionable, say the true thing instead.
  //
  // The deeper point: podman on macOS and Windows is a REMOTE client to a Linux VM, so the question
  // is not what this host has but what the podman machine has -- and a stock machine image ships
  // neither libkrun nor a +LIBKRUN crun. On Apple Silicon there is no path at all: applehv guests
  // get no /dev/kvm, and nested virtualisation needs M3+ and is not exposed by podman machine.
  if (microPlatform) {
    microReasons.push(microPlatform.reason)
    remediation.push(microPlatform.remediation)
  } else {
    const crun = sh('crun', ['--version'])
    if (crun.code !== 0) {
      microReasons.push('crun not found')
    } else if (!/LIBKRUN/i.test(crun.stdout + crun.stderr)) {
      microReasons.push('crun was not built with +LIBKRUN')
      remediation.push('install a crun built with libkrun support')
    }
    const hasLibkrun = [
      '/usr/lib/libkrun.so.1',
      '/usr/lib64/libkrun.so.1',
      '/usr/lib/libkrun.so'
    ].some(exists)
    if (!hasLibkrun) {
      microReasons.push('libkrun.so not found')
      remediation.push('pacman -S libkrun libkrunfw (or your distro equivalent)')
    }
    if (!exists('/dev/kvm')) {
      microReasons.push('/dev/kvm missing')
      remediation.push('enable KVM (nested virtualization if this is a VM)')
    }
  }
  results.push({
    ...RANKED('microvm'),
    available: microReasons.length === 0 && containerReasons.length === 0,
    reason: [...microReasons, ...containerReasons].join('; ') || null,
    remediation:
      remediation.join('; ') || (containerReasons.length ? 'bare scripts/build/agent.js' : null)
  })

  results.sort((a, b) => b.rank - a.rank)
  return { tiers: results, podman: version }
}

function RANKED(name) {
  return TIERS.find((t) => t.name === name)
}

// Pick the strongest available tier, or refuse. `min` defaults to the strongest tier, which is the
// safe default: opting DOWN is explicit and recorded, opting up is never needed.
function resolve(opts = {}) {
  const min = opts.min || 'microvm'
  if (RANK[min] === undefined) {
    throw WorkflowError.UNKNOWN_TIER(`unknown minimum tier ${JSON.stringify(min)}`)
  }

  const { tiers, podman } = probe(opts)
  const best = tiers.find((t) => t.available) || null

  if (!best || best.rank < RANK[min]) {
    throw WorkflowError.ISOLATION_UNAVAILABLE(explain(tiers, min, best))
  }
  return { tier: best.name, rank: best.rank, tiers, podman }
}

function explain(tiers, min, best) {
  const lines = [`no isolation tier meeting minimum '${min}' (rank ${RANK[min]}) is available`]
  for (const t of tiers) {
    const status = t.available
      ? `available (rank ${t.rank})${t.rank < RANK[min] ? ' -- BELOW MINIMUM' : ''}`
      : `unavailable: ${t.reason}`
    lines.push(`  ${t.name.padEnd(10)} ${status}`)
    if (!t.available && t.remediation) lines.push(`  ${''.padEnd(10)} fix: ${t.remediation}`)
  }
  lines.push('refusing to run at a weaker tier than required.')
  if (best) lines.push(`override with --tier ${best.name} if you accept the risk for this code.`)
  return lines.join('\n')
}

module.exports = { probe, resolve, explain, TIERS, RANK }
