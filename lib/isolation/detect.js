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
const env = require('bare-env')

const WorkflowError = require('./../errors.js')

// Ranked by what a full compromise of the workload actually buys an attacker, not by convenience.
const TIERS = [
  { name: 'microvm', rank: 90 },
  { name: 'container', rank: 50 }
]

const RANK = TIERS.reduce((acc, t) => ({ ...acc, [t.name]: t.rank }), {})

function sh(file, args, timeoutMs = 30000) {
  try {
    const r = spawnSync(file, args, {
      timeout: timeoutMs,
      env: { PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR }
    })
    return {
      code: r.status === null ? -1 : r.status,
      stdout: r.stdout ? r.stdout.toString() : '',
      stderr: r.stderr ? r.stderr.toString() : ''
    }
  } catch (err) {
    return { code: -1, stdout: '', stderr: String(err) }
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

// Probes are honest about WHY a tier is unavailable and how to fix it. "microvm unavailable" with no
// remediation is how a strong tier stays uninstalled forever.
function probe(opts = {}) {
  const image = opts.image || null
  const results = []

  const podman = sh('podman', ['version', '--format', '{{.Client.Version}}'])
  if (podman.code !== 0) {
    for (const tier of TIERS) {
      results.push({
        ...tier,
        available: false,
        reason: 'podman not found',
        remediation: 'install podman (rootless is fine)'
      })
    }
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
