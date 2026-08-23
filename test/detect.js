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

test('the machine tier sits between container and microvm, and says why', (t) => {
  // The whole reason this tier exists: on macOS and Windows podman is a remote client to a VM, so a
  // container escape lands in the VM rather than on the developer's laptop. Recording that as
  // `container` understates the boundary; recording it as `microvm` overstates it, because it is ONE
  // VM shared by every job where krun gives each job its own. The attestation is what makes the
  // difference matter -- the farm is meant to reject weakly-built artifacts on exactly this field.
  const machine = detect.TIERS.find((x) => x.name === 'machine')
  const container = detect.TIERS.find((x) => x.name === 'container')
  const micro = detect.TIERS.find((x) => x.name === 'microvm')

  t.ok(machine, 'the tier exists')
  t.ok(machine.rank > container.rank, 'a machine boundary outranks a shared kernel')
  t.ok(machine.rank < micro.rank, 'but a SHARED VM does not outrank a per-job one')
  t.is(detect.RANK.machine, machine.rank)

  // Still no host-execution tier: naming a weaker-than-microvm tier must not become a precedent for
  // one. Decision 3 is not softened by this.
  t.absent(detect.TIERS.some((x) => x.name === 'host' || x.name === 'emulation'))
})

test('the machine tier is a question for the SERVER, not the host platform', (t) => {
  // Deliberately not `os.platform() !== 'linux'`. A Linux user running a podman machine has the same
  // boundary a Mac user does, and a Mac with podman somehow local would not -- so the probe asks
  // podman whether its service is remote. Every tier still has to be accounted for either way.
  const probe = detect.probe()
  const machine = probe.tiers.find((x) => x.name === 'machine')
  t.ok(machine, 'reported in every probe')
  if (machine.available) {
    t.is(machine.shared, true, 'and flagged as SHARED, which is the whole caveat')
  } else {
    t.ok(machine.reason && machine.reason.length > 0, 'or says why not: ' + machine.reason)
    t.ok(machine.remediation && machine.remediation.length > 0, 'with something actionable')
  }
})

test('naming the machine tier does not unlock darwin-arm64', (t) => {
  // The trap this guards. `machine` is available on a Mac, and a careless reading of "we now have a
  // stronger tier on macOS" would be that the Mac can build its own platform. It cannot: the VM is a
  // LINUX guest, so codesign does not exist there and an arm64 Mach-O would be dead on arrival. That
  // is what TIER_PLATFORM encodes, and it is the single most expensive mistake this model prevents.
  const targets = require('../lib/targets.js')
  t.is(targets.TIER_PLATFORM.machine, 'linux', 'the machine tier executes on linux')
  t.is(
    targets.executionPlatform(['machine'], 'darwin'),
    'linux',
    'so a job on a Mac still runs in a Linux guest'
  )
  const caps = targets.describe({ tiers: ['machine'], platform: 'darwin', arch: 'arm64' })
  t.absent(
    caps.targets.includes('darwin-arm64'),
    'and darwin-arm64 stays refused: ' + caps.targets.join(', ')
  )
})

test('the seatbelt tier ranks BELOW container, and says why', (t) => {
  // The temptation is to rank a native tier highly because it is the newest and the only one that can
  // build darwin-arm64. Capability is not isolation strength. Seatbelt is kernel-enforced MAC on the
  // HOST kernel with no namespaces, no pid isolation, no separate filesystem and no capability model,
  // so it is genuinely weaker than a hardened container -- and the tier ranking is what a farm uses
  // to reject weakly-built artifacts, so overstating it is not a cosmetic error.
  const seatbelt = detect.TIERS.find((x) => x.name === 'seatbelt')
  const container = detect.TIERS.find((x) => x.name === 'container')
  t.ok(seatbelt, 'the tier is registered')
  t.ok(seatbelt.rank < container.rank, 'same-kernel MAC is weaker than a hardened container')
  t.is(detect.RANK.seatbelt, seatbelt.rank)

  // Still no unconfined host tier. Naming a weaker-than-container tier must not become the precedent
  // for one -- decision 3 forbids UNCONFINED host execution specifically, not native execution.
  t.absent(detect.TIERS.some((x) => x.name === 'host' || x.name === 'emulation'))
})

test('seatbelt is decided without asking podman', (t) => {
  // It needs no container runtime, so a stopped podman machine must not make it report unavailable.
  // Putting it inside the podman-failure loop would tell a Mac user their NATIVE tier is broken
  // because of podman -- false, and unactionable in the specific way this project keeps fixing.
  const withBadImage = detect
    .probe({ image: 'localhost/definitely-not-a-real-image:x' })
    .tiers.find((x) => x.name === 'seatbelt')
  const plain = detect.probe().tiers.find((x) => x.name === 'seatbelt')
  t.is(withBadImage.available, plain.available, 'a broken image does not change the verdict')
  t.is(withBadImage.reason, plain.reason, 'nor the reason')

  // And on a platform it can never work on, it says so as a fact about the platform rather than
  // offering a fix that cannot be followed.
  const onLinux = detect.probe({ platform: 'linux' }).tiers.find((x) => x.name === 'seatbelt')
  t.absent(onLinux.available, 'never available off macOS')
  t.ok(/macOS-only/.test(onLinux.reason), 'says why: ' + onLinux.reason)
  t.absent(onLinux.remediation, 'and offers no fix, because there is not one')
})

test('an available seatbelt tier is what unlocks darwin-arm64 -- and only then', (t) => {
  // The whole capability model in one assertion. TIER_PLATFORM.seatbelt = 'darwin' is what makes
  // darwin-arm64 legitimately buildable, but the gate is the PROBE: until the tier reports available,
  // nothing offers the target. Both halves matter -- the mapping without the gate over-promises, and
  // the gate without the mapping means a Mac can never build its own platform.
  const targets = require('../lib/targets.js')
  t.is(targets.TIER_PLATFORM.seatbelt, 'darwin', 'the tier executes on darwin')
  t.ok(
    targets
      .describe({ tiers: ['seatbelt'], platform: 'darwin', arch: 'arm64' })
      .targets.includes('darwin-arm64'),
    'so a job on it can build darwin-arm64'
  )

  // What doctor and validate actually report: derived from AVAILABLE tiers only.
  const probe = detect.probe()
  const available = probe.tiers.filter((x) => x.available).map((x) => x.name)
  const caps = targets.describe({ tiers: available })
  const seatbelt = probe.tiers.find((x) => x.name === 'seatbelt')
  if (seatbelt.available) {
    t.ok(caps.targets.includes('darwin-arm64'), 'available here, so the target is offered')
  } else {
    t.absent(
      caps.targets.includes('darwin-arm64'),
      `unavailable here (${seatbelt.reason}), so the target is NOT offered`
    )
  }
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

test('setup checks report what is wrong, and never pass when they cannot tell', (t) => {
  // These exist because each of the three fails LATE and looks like something else: a machine
  // smaller than the limits is a guest OOM-kill reported as `podman exited <n>`, a checkout the
  // podman service cannot see is a seccomp error naming a path that plainly exists on the host, and
  // a missing bare-build used to be exit 144 with no output whatsoever.
  const checks = detect.setupChecks({ requiredBytes: 8 * 1024 ** 3 })
  t.ok(Array.isArray(checks) && checks.length > 0, 'returns records, not printed output')

  for (const c of checks) {
    t.ok(typeof c.name === 'string' && c.name.length > 0, `named: ${c.name}`)
    t.ok(typeof c.detail === 'string' && c.detail.length > 0, `${c.name} explains itself`)
    // The important one. `ok: null` means "could not determine", and it must be distinguishable
    // from `true` -- a setup check that reports success when it could not look is the vacuous-pass
    // failure mode this project keeps finding.
    t.ok(c.ok === true || c.ok === false || c.ok === null, `${c.name} is tri-state, not boolean`)
  }

  // bare-build is always reported: it is a host fact, so the answer never depends on podman.
  t.ok(
    checks.some((c) => c.name === 'bare-build'),
    'bare-build is always checked'
  )
})

test('the memory check asks for more than the shortfall', (t) => {
  // A podman machine created with `--memory 8192` reports ~7.73 GiB to containers -- the hypervisor
  // and guest kernel take their cut. So advising exactly the requirement yields the worst kind of
  // remediation: one that tells you to set the value you have already set. Observed for real.
  const mem = detect
    .setupChecks({ requiredBytes: 8 * 1024 ** 3, platform: 'darwin' })
    .find((c) => c.name === 'runtime memory')
  t.ok(mem, 'the check exists')
  if (mem.ok !== false) {
    t.comment('this machine satisfies the requirement; nothing to advise')
    return t.pass('skipped the advice assertion')
  }
  const suggested = Number((mem.detail.match(/--memory (\d+)/) || [])[1] || 0)
  t.ok(suggested > 8192, `advises more than the requirement, not equal to it: ${suggested}`)
})

test('a checkout the runtime cannot see is caught, not discovered at runtime', (t) => {
  // /Volumes is NOT mounted into a podman machine (measured), and the seccomp profile is an absolute
  // host path read by the service INSIDE the VM. Without this the failure is
  // "opening seccomp profile failed" naming a file that exists on your Mac.
  const remote = detect.probe().tiers.find((x) => x.name === 'machine')
  if (!remote || !remote.available) {
    t.comment('the container runtime is local here, so visibility is trivially satisfied')
    return t.pass('skipped')
  }
  const bad = detect
    .setupChecks({ dir: '/Volumes/nope/checkout', platform: 'darwin' })
    .find((c) => c.name === 'checkout visible to the runtime')
  t.ok(bad, 'the check runs when the runtime is remote')
  t.is(bad.ok, false, '/Volumes is refused')
  t.ok(/seccomp/i.test(bad.detail), 'and names the failure it prevents')

  const good = detect
    .setupChecks({ dir: '/Users/someone/src', platform: 'darwin' })
    .find((c) => c.name === 'checkout visible to the runtime')
  t.is(good.ok, true, 'while a normal checkout under /Users passes')
})

test('a non-Linux host is told the truth, not a pacman command', (t) => {
  // Decision 4 (refuse rather than degrade) rests entirely on the remediation being actionable --
  // "It is the only thing that makes anyone install libkrun." On a Mac the old probes looked for
  // `/usr/lib/libkrun.so.1` and `/dev/kvm`, got the right ANSWER for the wrong reason, and printed
  // `pacman -S libkrun libkrunfw`. That is the project's first impression on macOS.
  for (const platform of ['darwin', 'win32']) {
    const micro = detect.probe({ platform }).tiers.find((x) => x.name === 'microvm')
    t.absent(micro.available, `${platform}: krun is not reachable`)
    t.ok(/Linux-only/.test(micro.reason), `${platform}: says why`)
    t.absent(/pacman/.test(micro.remediation || ''), `${platform}: no unfollowable advice`)
    t.absent(/dev\/kvm/.test(micro.reason), `${platform}: does not claim a missing device file`)
    // The honest alternative, and the design question it raises: a podman machine IS a VM boundary,
    // but one shared across every job -- unlike krun, where each job gets its own.
    t.ok(/SHARED/.test(micro.remediation || ''), `${platform}: names the real trade-off`)
  }

  // Unchanged on Linux: the real probes still run and still name real fixes.
  const linux = detect.probe({ platform: 'linux' }).tiers.find((x) => x.name === 'microvm')
  t.absent(/Linux-only/.test(linux.reason || ''), 'linux still probes for real')
})
