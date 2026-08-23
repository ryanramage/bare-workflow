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
//
// `machine` sits between the two deliberately. When podman is a remote client -- always the case on
// macOS and Windows, where the service lives inside a `podman machine` VM -- a container escape does
// not land on your laptop, it lands in the VM. That is a genuine machine boundary and calling it
// `container` understates it. But it is ONE VM shared by every job, where krun gives each job its
// own, so calling it `microvm` overstates it just as badly. Both understatements matter because the
// tier is recorded in the attestation and the farm is meant to reject weakly-built artifacts on it.
const TIERS = [
  { name: 'microvm', rank: 90 },
  { name: 'machine', rank: 70 },
  { name: 'container', rank: 50 },
  // Below `container`, deliberately. Seatbelt is kernel-enforced MAC on the HOST kernel: no
  // namespaces, no pid isolation, no separate filesystem, no capability model. It is a real boundary
  // -- measured: a `(deny default)` profile refuses `cat ~/.ssh/id_ed25519` and fails closed, denying
  // even execvp when nothing is allowed -- but it is weaker than a hardened container, and ranking it
  // higher because it is the newest thing here would be exactly the overstatement `machine` was added
  // to fix. It exists because it is the ONLY tier that can produce darwin-arm64.
  { name: 'seatbelt', rank: 40 }
]

// Where the generated Seatbelt profile lives. Resolved relative to this file so it works whatever
// the cwd is -- the same reason bin.js resolves the seccomp profile from __dirname.
const SANDBOX_PROFILE = require('bare-path').join(__dirname, '../../etc/sandbox/build-v1.sb')

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
      'containers here already run inside a podman-machine VM, which IS a machine boundary but is ' +
      'SHARED between jobs rather than per-job; that posture is the `machine` tier -- ' +
      'use --tier machine to accept it explicitly'
  }
}

// The seatbelt verdict, as a tier record. Kept next to platformMicrovm() because both answer a
// question about the host that no amount of container-runtime health can change.
function seatbeltTier(platform, opts = {}) {
  const darwin = require('./darwin/probe.js')
  const verdict = darwin.probe({ platform, profile: opts.sandboxProfile || SANDBOX_PROFILE })
  return {
    ...RANKED('seatbelt'),
    available: verdict.available,
    reason: verdict.reason,
    remediation: verdict.remediation,
    // Each job gets its own sandbox-exec process, but every job shares this machine's kernel, user
    // and filesystem. `false` would read as "isolated per job" and overstate it by a wide margin.
    shared: verdict.available ? true : null
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
  // Seatbelt needs no container runtime at all, so it is decided before podman is asked and is
  // reported identically whether podman answers or not. Putting it inside the failure loop below
  // would tell a Mac user with a stopped podman machine that their NATIVE tier is unavailable because
  // of podman, which is both false and unactionable.
  const seatbelt = seatbeltTier(platform, opts)

  const podman = sh('podman', ['info', '--format', '{{.Version.Version}}'])
  if (podman.code !== 0) {
    const { reason, remediation } = diagnosePodman(podman)
    for (const tier of TIERS) {
      if (tier.name === 'seatbelt') {
        results.push(seatbelt)
        continue
      }
      // microvm keeps its platform verdict even here -- see above. `machine` cannot be decided
      // without asking the server, so it correctly inherits the podman failure.
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

  results.push(seatbelt)

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

  // machine tier: is the container runtime a different machine from this one?
  //
  // `serviceIsRemote` is podman's own answer, and it is the right question to ask -- it is true for a
  // podman-machine VM (macOS, Windows, and Linux if you use one) and for a genuinely remote podman
  // host. Either way the property that matters holds: a container escape does not land on THIS
  // machine. Asked of the server rather than inferred from os.platform(), so a Linux user running a
  // podman machine gets the same honest answer a Mac user does.
  const remote = sh('podman', ['info', '--format', '{{.Host.ServiceIsRemote}}'])
  const isRemote = remote.code === 0 && remote.stdout.trim() === 'true'
  const machineReasons = [...containerReasons]
  if (!isRemote) {
    machineReasons.push('containers run directly on this host, so there is no machine boundary')
  }
  results.push({
    ...RANKED('machine'),
    available: machineReasons.length === 0,
    reason: machineReasons.join('; ') || null,
    remediation: machineReasons.length
      ? containerReasons.length
        ? 'bare scripts/build/agent.js'
        : 'this tier exists where podman is a remote client (a podman machine VM, or a remote host)'
      : null,
    // Recorded so the attestation says WHAT the boundary was, not just that there was one. A shared
    // VM and a dedicated remote builder are both `machine` but they are not the same promise.
    shared: isRemote ? true : null
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

// Setup facts that are easy to get wrong and mostly fail LATE, as something that looks unrelated.
//
// Each of these was hit for real bringing macOS up, and none of them was checked as a set:
//
//   * A podman machine smaller than the default limits. tmpfs is charged to the memory cgroup, so a
//     4 GiB /w inside a 2 GiB VM is not "disk full", it is a guest OOM-kill presenting as
//     `podman exited <n>`. resolveLimits() validates the sizes against each other but has no way to
//     know the machine's real capacity -- that is a server-side fact, so it is asked for here.
//   * A checkout the podman service cannot see. The seccomp profile is an absolute HOST path read
//     inside the VM. podman machine mounts /Users and /private on macOS; a clone under /Volumes
//     fails with "opening seccomp profile failed" naming a path that plainly exists on the host.
//   * `bare-build` missing. Needed to build the agent, and its absence used to be exit 144 with no
//     output at all.
//
// Returned as records rather than printed, so `doctor` renders them and a test can assert on them.
// Every check reports `ok: null` when it genuinely cannot tell, which is never the same as passing.
function setupChecks(opts = {}) {
  const checks = []
  const platform = opts.platform || os.platform()
  const need = opts.requiredBytes || 0

  // --- the container runtime's memory, versus what a run will ask for -----------------
  const mem = sh('podman', ['info', '--format', '{{.Host.MemTotal}}'])
  const total = mem.code === 0 ? Number(mem.stdout.trim()) : NaN
  if (!Number.isFinite(total) || total <= 0) {
    checks.push({
      name: 'runtime memory',
      ok: null,
      detail: 'could not ask podman how much memory the container runtime has'
    })
  } else {
    const gib = (n) => (n / 1024 ** 3).toFixed(1) + ' GiB'
    const ok = need === 0 ? true : total >= need
    checks.push({
      name: 'runtime memory',
      ok,
      detail: ok
        ? `${gib(total)} available to containers`
        : `${gib(total)} available to containers, but the default limits want ${gib(need)}. ` +
          (platform === 'linux'
            ? 'Lower the limits, or run on a bigger machine.'
            : // Deliberately ASKS FOR MORE than the shortfall. A podman machine created with
              // --memory 8192 reports ~7.73 GiB to containers, because the hypervisor and guest
              // kernel take their cut -- so advising exactly the requirement produces the worst kind
              // of remediation: one that tells you to set the value you already set. Round up to the
              // next GiB above the requirement and add a GiB of headroom.
              'Resize in place: podman machine set --memory ' +
              (Math.ceil(need / 1024 ** 3) + 1) * 1024 +
              ' (no need to recreate it)')
    })
  }

  // --- can the podman service see this checkout? --------------------------------------
  //
  // Only meaningful where the service is remote; on a local Linux podman the answer is trivially
  // yes and asserting it would be noise.
  const remote = sh('podman', ['info', '--format', '{{.Host.ServiceIsRemote}}'])
  const isRemote = remote.code === 0 && remote.stdout.trim() === 'true'
  if (isRemote) {
    const dir = opts.dir || os.cwd()
    // Measured on macOS: podman machine bind-mounts /Users and /private via virtiofs, and nothing
    // else. This is a prefix test rather than a probe because probing would need a container.
    const mounted = platform === 'darwin' ? ['/Users/', '/private/', '/var/folders/'] : null
    if (mounted && !mounted.some((m) => (dir + '/').startsWith(m))) {
      checks.push({
        name: 'checkout visible to the runtime',
        ok: false,
        detail:
          `${dir} is not under a path the podman machine mounts (${mounted.join(', ')}). ` +
          'The seccomp profile is read by the service inside the VM, so a run will fail with ' +
          '"opening seccomp profile failed". Move the checkout.'
      })
    } else {
      checks.push({
        name: 'checkout visible to the runtime',
        ok: true,
        detail: `${dir} is reachable from the container runtime`
      })
    }
  }

  // --- the agent toolchain -------------------------------------------------------------
  const bb = which('bare-build')
  checks.push({
    name: 'bare-build',
    ok: bb !== null,
    detail: bb || 'not on PATH -- needed to build the agent: npm i -g bare-build'
  })

  return checks
}

function RANKED(name) {
  return TIERS.find((t) => t.name === name)
}

// Pick the strongest available tier, or refuse. `min` defaults to the strongest tier, which is the
// safe default: opting DOWN is explicit and recorded, opting up is never needed.
// Pick a tier, given a minimum and -- optionally -- what the run actually needs to build.
//
// `opts.targets` is what makes this more than "strongest wins". Rank and CAPABILITY are orthogonal,
// and that only became visible when the seatbelt tier arrived: it is the weakest tier here (rank 40)
// and simultaneously the only one that can produce darwin-arm64, because it is the only one that
// executes on macOS. Ranking alone therefore answers "give me darwin-arm64" with `machine`, which
// cannot build it -- silently, since the target is simply skipped later as unsupported.
//
// So: among available tiers at or above the minimum, prefer the STRONGEST one that can build
// everything asked for. Fall back to the strongest available when nothing covers the whole set, which
// preserves the old behaviour exactly for a run that declares no targets or targets no tier can cover
// -- those are then skipped downstream with a stated reason, as before.
//
// Known limitation, worth stating rather than discovering: this is per-RUN, not per-task. A workflow
// mixing darwin-arm64 with linux targets picks seatbelt for all of them, so the linux builds get a
// weaker tier than they need. Per-task resolution is the right end state and is the same shape as the
// farm's routing decision, which is why it is not being bodged in here.
function resolve(opts = {}) {
  const min = opts.min || 'microvm'
  if (RANK[min] === undefined) {
    throw WorkflowError.UNKNOWN_TIER(`unknown minimum tier ${JSON.stringify(min)}`)
  }

  const { tiers, podman } = probe(opts)
  const wanted = (opts.targets || []).filter(Boolean)
  const eligible = tiers.filter((t) => t.available && t.rank >= RANK[min])
  const capable = wanted.length ? eligible.filter((t) => coversAll(t.name, wanted)) : []
  const best = capable[0] || tiers.find((t) => t.available) || null

  if (!best || best.rank < RANK[min]) {
    throw WorkflowError.ISOLATION_UNAVAILABLE(explain(tiers, min, best))
  }
  // `shared` rides along so the attestation can record WHAT the boundary was, not just its name.
  return {
    tier: best.name,
    rank: best.rank,
    shared: best.shared === undefined ? null : best.shared,
    tiers,
    podman
  }
}

// Can everything the run asked for be built on this tier's execution platform?
function coversAll(tier, wanted) {
  const targets = require('./../targets.js')
  const platform = targets.TIER_PLATFORM[tier]
  // A tier we do not have a platform for cannot be reasoned about; do not claim it covers anything.
  if (!platform) return false
  return wanted.every((target) => targets.buildableOn(platform, target))
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

module.exports = { probe, resolve, explain, setupChecks, TIERS, RANK }
