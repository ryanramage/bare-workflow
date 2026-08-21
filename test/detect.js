'use strict'

// Tier detection and the refuse-to-run policy.
//
// The policy is the part worth testing, not the probing: if the best available tier is below the
// required minimum, the runner exits rather than running. wrkflw does the opposite -- Docker
// unavailable means quietly running on the host -- and that is the failure mode this exists to
// prevent, so "it refused, and said how to fix it" is the assertion.

const test = require('brittle')
const detect = require('../lib/isolation/detect.js')

test('tiers are ranked by what a compromise actually buys an attacker', (t) => {
  const micro = detect.TIERS.find((x) => x.name === 'microvm')
  const container = detect.TIERS.find((x) => x.name === 'container')
  t.ok(micro.rank > container.rank, 'a separate guest kernel outranks a shared one')
  t.is(detect.RANK.microvm, micro.rank)
  // There is deliberately no host-execution tier: a command allowlist over host processes is
  // defeated by the first `sh -c`.
  t.absent(detect.TIERS.some((x) => x.name === 'host' || x.name === 'emulation'))
})

test('probing reports why a tier is unavailable, and how to fix it', (t) => {
  const probe = detect.probe({ image: 'localhost/definitely-not-a-real-image:x' })
  t.is(probe.tiers.length, detect.TIERS.length, 'every tier is accounted for')
  for (const tier of probe.tiers) {
    if (tier.available) continue
    t.ok(tier.reason && tier.reason.length > 0, `${tier.name} says why: ${tier.reason}`)
    t.ok(tier.remediation && tier.remediation.length > 0, `${tier.name} says how to fix it`)
  }
  t.ok(probe.tiers[0].rank >= probe.tiers[probe.tiers.length - 1].rank, 'sorted strongest first')
})

test('an unknown minimum tier is rejected', (t) => {
  t.exception(() => detect.resolve({ min: 'emulation' }), /UNKNOWN_TIER/)
  t.exception(() => detect.resolve({ min: 'whatever' }), /UNKNOWN_TIER/)
})

test('the refusal message names the tiers, the reasons, and the remedy', (t) => {
  // Built from a synthetic probe so the assertion holds regardless of what this machine supports.
  const tiers = [
    {
      name: 'microvm',
      rank: 90,
      available: false,
      reason: 'libkrun.so not found',
      remediation: 'pacman -S libkrun libkrunfw'
    },
    { name: 'container', rank: 50, available: true, reason: null, remediation: null }
  ]
  const message = detect.explain(tiers, 'microvm', tiers[1])

  t.ok(/minimum 'microvm'/.test(message), 'states the requirement')
  t.ok(/libkrun\.so not found/.test(message), 'states why the strong tier is missing')
  t.ok(/pacman -S libkrun/.test(message), 'states the fix')
  t.ok(/BELOW MINIMUM/.test(message), 'flags the available-but-too-weak tier')
  t.ok(/refusing to run/.test(message), 'and is explicit that it refused')
  t.ok(
    /--tier container/.test(message),
    'while naming the override for someone who accepts the risk'
  )
})

test('a weaker-but-available tier is accepted when the minimum allows it', (t) => {
  // Opting DOWN is explicit and recorded; it is never the default.
  const probe = detect.probe()
  const anyAvailable = probe.tiers.some((x) => x.available)
  if (!anyAvailable) {
    t.comment('no tier available on this machine; skipping')
    return t.pass('skipped')
  }
  const resolved = detect.resolve({ min: 'container' })
  t.ok(detect.RANK[resolved.tier] >= detect.RANK.container)
  t.ok(resolved.tiers.length > 0, 'the full probe is returned for the attestation')
})
