'use strict'

// Pure spec -> argv. THE security-critical file in this project.
//
// Everything here is a pure function: no spawning, no filesystem, no environment reads. That is
// deliberate -- it means the entire isolation posture is unit-testable with zero containers, and
// a snapshot test can pin the exact argv so any accidental weakening shows up as a reviewable
// diff in a PR rather than as a silent regression.
//
// Two invariants are enforced structurally, not by convention:
//
//   1. NO HOST BIND MOUNTS, EVER. We could not have them even if we wanted: podman-run(1) says
//      idmap is rootful-only because "the Linux kernel does not allow the use of idmapped file
//      systems for unprivileged users", so a bind mount under --userns=auto lands as `nobody` and
//      is unwritable. Rather than fight that, we exploit it: all data crosses the boundary as a
//      validated tar stream, which also deletes the entire bind-mount attack surface and the
//      host-path-rebasing subsystem that wrkflw needs.
//
//   2. NO HOST ENVIRONMENT INHERITANCE. bare-subprocess defaults `env` to the parent's
//      environment, so the caller is one omission away from handing GH_TOKEN to a build. The env
//      handed to the podman client is constructed explicitly by the caller of this module, and the
//      env handed to the workload is an allowlist assembled below.
//
// Tier note that matters for anyone reading the flags: under the microvm tier the guest runs its
// own kernel, so --cap-drop/--security-opt do NOT constrain the workload (measured: uid 0 with a
// full CapEff inside a krun guest). The VM is the boundary there. We still emit them, because they
// confine the host-side VMM process and cost nothing. The escape tests therefore have to be
// tier-aware -- asserting CapEff==0 inside a microVM is a wrong test, not a finding.

const WorkflowError = require('../../errors.js')

const TIERS = ['microvm', 'container']

// Flags that must never appear in a generated argv. Checked by assertSafe() against the finished
// argv, so this survives refactors of the builder itself.
const FORBIDDEN = [
  '--privileged',
  '--env-host',
  '--volumes-from',
  '--group-add',
  '--publish',
  '-p',
  '-v',
  '--volume',
  '--cap-add',
  '--uidmap',
  '--gidmap',
  '--subuidname',
  '--subgidname'
]

// Flag=value pairs that must never appear, as (flag, predicate) pairs.
const FORBIDDEN_VALUES = [
  ['--network', (v) => v === 'host'],
  ['--pid', (v) => v === 'host'],
  ['--ipc', (v) => v === 'host'],
  ['--uts', (v) => v === 'host'],
  ['--cgroupns', (v) => v === 'host'],
  ['--userns', (v) => v === 'host' || v === 'keep-id' || v === 'nomap' || v.startsWith('keep-id')],
  [
    '--security-opt',
    (v) => v === 'seccomp=unconfined' || v === 'label=disable' || v.startsWith('unmask')
  ],
  ['--mount', (v) => /(^|,)type=bind(,|$)/.test(v)],
  ['--device', (v) => v !== '/dev/kvm']
]

const DEFAULTS = {
  workspace: '/w',
  workdir: '/w/src',
  cachePath: '/cache',
  agent: '/opt/bw/agent',
  usernsSize: 1024,
  // These four are NOT independent, and getting that wrong is what the assertion below exists for.
  // A tmpfs is RAM-backed, so every byte written to /w, /tmp or /dev/shm is charged to the memory
  // cgroup. Measured: 1500 MiB written into a 4 GiB tmpfs under `--memory 1g` is OOM-KILLED at
  // ~1020 MiB, not given ENOSPC. So `tmpfs-size` is an upper bound that the memory limit can make
  // unreachable, and the old defaults (8 GiB of workspace under a 4 GiB memory cap) promised a
  // workspace twice the size of the one you could actually fill -- and turned "the disk filled up"
  // into "SIGKILL", which is a far worse thing to debug.
  memoryBytes: 8 * 1024 * 1024 * 1024,
  workspaceBytes: 4 * 1024 * 1024 * 1024,
  tmpBytes: 1024 * 1024 * 1024,
  shmBytes: 64 * 1024 * 1024,
  // What must stay available to the processes themselves after the tmpfs mounts are accounted for.
  // npm extracting a large dependency tree wants a few hundred MiB on its own.
  headroomBytes: 1024 * 1024 * 1024,
  pids: 512,
  // 4096 was too low, and the way it failed is worth recording because nothing pointed at fds.
  // `bare-pack` traverses a dependency graph with UNBOUNDED concurrency (its `concurrency` option
  // defaults to 0, i.e. no semaphore) and its `readModule` swallows every errno -- a failed read
  // returns null, which is indistinguishable from a missing file. So EMFILE surfaces as
  // `MODULE_NOT_FOUND: Cannot find module 'b4a'` for a module sitting right there on disk.
  // Measured on hello-pear-bare (140 packages): 330-593 EMFILE errors per build at 4096 fds, a
  // DIFFERENT module named each run, roughly a 2-in-3 failure rate. The dependency graph is the
  // input, so a toy project builds fine and a real one does not -- which is the worst shape for a
  // default to have.
  nofile: 65536,
  nproc: 512,
  wallClockMs: 3600 * 1000,
  cpuQuota: 2
}

// podman and systemd disagree on byte syntax, and the mismatch is silent until you actually run
// it: systemd rejects podman's 'b' suffix outright with
//   "Failed to parse MemoryMax= value '4294967296b': Invalid argument"
// Two formatters, so neither side can borrow the other's spelling.
function podmanBytes(n) {
  return String(n) + 'b'
}

function systemdBytes(n) {
  return String(n) // bare integer == bytes; K/M/G suffixes also valid, 'b' is not
}

function assertSpec(spec) {
  if (!spec || typeof spec !== 'object') {
    throw WorkflowError.INVALID_SPEC('spec must be an object')
  }
  if (!spec.jobId || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(spec.jobId)) {
    throw WorkflowError.INVALID_SPEC(
      `jobId must match /^[a-z0-9][a-z0-9-]{0,62}$/, got ${JSON.stringify(spec.jobId)}`
    )
  }
  if (!TIERS.includes(spec.tier)) {
    throw WorkflowError.UNKNOWN_TIER(
      `tier must be one of ${TIERS.join('|')}, got ${JSON.stringify(spec.tier)}`
    )
  }
  if (!spec.image || typeof spec.image.ref !== 'string' || !spec.image.ref) {
    throw WorkflowError.INVALID_SPEC('image.ref is required')
  }
  // Image choice is a trusted-only field: an unpinned tag lets whoever controls the registry
  // swap the contents of the sandbox out from under an attestation.
  if (typeof spec.image.digest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(spec.image.digest)) {
    throw WorkflowError.IMAGE_NOT_PINNED(
      `image.digest must be sha256:<64 hex>, got ${JSON.stringify(spec.image.digest)}`
    )
  }
  if (spec.mounts) {
    for (const m of spec.mounts) {
      if (m && (m.type === 'bind' || m.hostPath || m.src)) {
        throw WorkflowError.HOST_MOUNT_REFUSED(
          `host bind mounts are structurally forbidden (got ${JSON.stringify(m)}); ` +
            'transfer data with sandbox.put()/get() instead'
        )
      }
    }
  }
  const net = (spec.network && spec.network.mode) || 'none'
  if (net !== 'none' && net !== 'proxy') {
    throw WorkflowError.INVALID_SPEC(`network.mode must be none|proxy, got ${JSON.stringify(net)}`)
  }
  if (spec.env) {
    for (const k of Object.keys(spec.env)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) {
        throw WorkflowError.INVALID_SPEC(`env key ${JSON.stringify(k)} is not a valid identifier`)
      }
      if (typeof spec.env[k] !== 'string') {
        throw WorkflowError.INVALID_SPEC(`env value for ${k} must be a string`)
      }
    }
  }
}

// The limits are checked together, not one at a time, because the failure they cause is a
// relationship rather than a value: any individual number here is reasonable.
function resolveLimits(spec) {
  const o = { ...DEFAULTS, ...(spec.limits || {}) }
  const tmpfsTotal = o.workspaceBytes + o.tmpBytes + o.shmBytes
  if (tmpfsTotal + o.headroomBytes > o.memoryBytes) {
    const mb = (n) => Math.round(n / (1024 * 1024)) + ' MiB'
    throw WorkflowError.INVALID_SPEC(
      'tmpfs sizes exceed the memory limit, so the workspace cap can never be reached:\n' +
        `  workspace ${mb(o.workspaceBytes)} + /tmp ${mb(o.tmpBytes)} + shm ${mb(o.shmBytes)}` +
        ` = ${mb(tmpfsTotal)} of RAM-backed storage\n` +
        `  plus ${mb(o.headroomBytes)} of process headroom, against a memory limit of ${mb(o.memoryBytes)}\n` +
        '  tmpfs pages are charged to the memory cgroup, so filling the workspace would be an\n' +
        '  OOM-kill (exit 137) rather than ENOSPC. Raise memoryBytes or shrink the tmpfs sizes.'
    )
  }
  return o
}

// Build the podman portion of the argv.
function podmanArgs(spec) {
  const o = resolveLimits(spec)
  const caps = spec.capabilities || {}
  const net = (spec.network && spec.network.mode) || 'none'
  const args = ['run', '--rm', '--name', 'bw-' + spec.jobId]

  if (spec.cidFile) args.push('--cidfile', spec.cidFile)

  // Never pull at run time: the image must already be present and digest-pinned, so a job cannot
  // spend unbounded bandwidth/disk or stage an exploit payload by naming an arbitrary registry.
  args.push('--pull', 'never')

  // journald is the default log driver here; an untrusted build must not be able to write
  // unbounded data into the host journal. Logs come over the agent stream where we rate-limit.
  args.push('--log-driver', 'none')

  // stdin open, no TTY: the agent protocol rides fds 0/1 and a TTY would merge stdout+stderr
  // and inject carriage returns. Verified byte-exact in test/fidelity.js.
  args.push('-i')
  args.push('--hostname', 'sandbox')

  if (spec.tier === 'microvm') {
    // crun is built +LIBKRUN and selects the microVM path by annotation, NOT by --runtime.
    args.push('--annotation', 'run.oci.handler=krun')
    args.push('--device', '/dev/kvm')
  }

  // Highest-value single flag: host uid is deliberately NOT mapped in, so even a full
  // container-root compromise is a subuid that owns nothing on the host.
  args.push('--userns', 'auto:size=' + o.usernsSize)
  args.push('--user', '1000:1000')
  args.push('--pid', 'private')
  args.push('--ipc', 'private')
  args.push('--uts', 'private')
  args.push('--cgroupns', 'private')

  args.push('--cap-drop', 'ALL')
  args.push('--security-opt', 'no-new-privileges')
  if (spec.seccompProfile) args.push('--security-opt', 'seccomp=' + spec.seccompProfile)

  const procOpts = ['nosuid', 'nodev', 'noexec']
  if (caps.hidepid !== false) procOpts.push('hidepid=2')
  args.push('--security-opt', 'proc-opts=' + procOpts.join(','))
  args.push(
    '--security-opt',
    'mask=/proc/scsi:/sys/firmware:/sys/devices/virtual/powercap:/proc/kcore:/proc/keys'
  )
  args.push('--umask', '0022')

  // Immutable rootfs. --read-only-tmpfs defaults to true and would silently hand back rw /dev,
  // /dev/shm, /run, /tmp and /var/tmp; disable it so every writable path is declared here and
  // therefore auditable in one place.
  args.push('--read-only')
  args.push('--read-only-tmpfs=false')

  // The workspace is a size-capped tmpfs rather than a podman volume: volumes on overlay have no
  // size limit, so `dd if=/dev/zero of=/w/big` would fill the host's /home. Losing the workspace
  // when the container dies is fine, because artifacts leave over the agent stream anyway.
  // tmpfs-mode=1777 is load-bearing, not laziness. A tmpfs mounts as root:root 0755 regardless of
  // what the image chowned at build time (the mount covers it), so with --user 1000:1000 the step
  // cannot create anything in its own workspace. The failure mode is confusing rather than obvious:
  // podman creates --workdir as root BEFORE dropping privileges, so `pwd` works and only writes
  // fail. Sticky+world-writable is fine here -- there is exactly one uid in the sandbox that
  // matters, and subdirectories the agent creates land as that uid at 0755.
  args.push(
    '--mount',
    `type=tmpfs,dst=${o.workspace},tmpfs-size=${o.workspaceBytes},tmpfs-mode=1777,nosuid,nodev`
  )
  if (spec.cacheVolume) {
    args.push(
      '--mount',
      `type=volume,src=${spec.cacheVolume},dst=${o.cachePath},ro,nosuid,nodev,noexec`
    )
  }
  // /tmp is deliberately WITHOUT noexec: cmake/ninja/node-gyp exec from temp dirs and noexec
  // breaks real builds while buying little, since memfd_create stays allowed for toolchains.
  args.push('--tmpfs', `/tmp:rw,nosuid,nodev,size=${o.tmpBytes},mode=1777`)
  args.push('--tmpfs', `/run:rw,nosuid,nodev,noexec,size=16m,mode=0755`)
  args.push('--shm-size', podmanBytes(o.shmBytes))

  args.push('--network', net === 'none' ? 'none' : 'bw-egress-' + spec.jobId)
  args.push('--no-hosts')
  // NOTE: --dns=none is intentionally NOT emitted. podman rejects it outright when combined with
  // --network none ("conflicting options: dns and the network mode: none"). With no network there
  // is no resolver to disable, so the flag is both redundant and fatal.

  args.push('--memory', podmanBytes(o.memoryBytes))
  args.push('--memory-swap', podmanBytes(o.memoryBytes)) // equal to --memory == swap disabled
  args.push('--pids-limit', String(o.pids))
  args.push('--ulimit', `nofile=${o.nofile}:${o.nofile}`)
  args.push('--ulimit', `nproc=${o.nproc}:${o.nproc}`)
  args.push('--ulimit', 'core=0:0')
  args.push('--timeout', String(Math.ceil(o.wallClockMs / 1000)))

  // --workdir is the WORKSPACE ROOT, not /w/src, and that distinction is load-bearing.
  //
  // podman creates the workdir as root BEFORE dropping to --user, so naming /w/src here produces a
  // root-owned 0755 directory that the step then cannot write to -- while `pwd` still works, which
  // makes it look like the workspace is fine. Pointing at /w (mode 1777) instead lets the agent
  // create src/home/artifacts itself, so they land owned by the uid that actually runs steps.
  // Steps still default to /w/src; that default lives in the step frame, not here.
  args.push('--workdir', o.workspace)

  const env = {
    HOME: o.workspace + '/home',
    TMPDIR: '/tmp',
    PATH: '/usr/local/bin:/usr/bin:/bin',
    CI: 'true',
    BW_JOB: spec.jobId,
    // The agent recreates its subtree here at startup, because the workspace tmpfs arrives empty.
    BW_WORKSPACE: o.workspace,
    ...(spec.env || {})
  }
  for (const k of Object.keys(env).sort()) args.push('--env', `${k}=${env[k]}`)

  args.push('--entrypoint', spec.agent || o.agent)
  args.push(`${spec.image.ref}@${spec.image.digest}`)

  return args
}

// systemd-run wrapper. This is the ONLY way to get CPU/IO limits from a normal login session
// here: podman reports CgroupControllers=[memory pids] because the interactive scope has only
// those delegated, so --cpus is silently inert. systemd enables the controllers on the
// intermediate slices for us, and gives an independent kill boundary + wall-clock backstop.
function scopeArgs(spec) {
  const o = resolveLimits(spec)
  return [
    '--user',
    '--scope',
    '--quiet',
    '--collect',
    '--unit=bw-job-' + spec.jobId,
    '-p',
    'MemoryMax=' + systemdBytes(o.memoryBytes),
    '-p',
    'MemorySwapMax=0',
    '-p',
    'CPUQuota=' + Math.round(o.cpuQuota * 100) + '%',
    '-p',
    'TasksMax=' + o.pids,
    '-p',
    'IOWeight=10',
    // Deliberately longer than podman's --timeout so the layers fire in order and we can tell
    // which one tripped.
    '-p',
    'RuntimeMaxSec=' + (Math.ceil(o.wallClockMs / 1000) + 300)
  ]
}

// Scan a finished argv for anything forbidden. Called by build() on its own output, so it guards
// against future refactors of the builder rather than just validating the spec.
function assertSafe(argv) {
  for (let i = 0; i < argv.length; i++) {
    const tok = argv[i]
    if (FORBIDDEN.includes(tok)) {
      throw WorkflowError.FORBIDDEN_FLAG(`${tok} must never appear in a sandbox argv`)
    }
    const eq = tok.indexOf('=')
    const flag = eq === -1 ? tok : tok.slice(0, eq)
    const inlineVal = eq === -1 ? null : tok.slice(eq + 1)
    for (const [f, bad] of FORBIDDEN_VALUES) {
      if (flag !== f) continue
      const val = inlineVal !== null ? inlineVal : argv[i + 1]
      if (typeof val === 'string' && bad(val)) {
        throw WorkflowError.FORBIDDEN_FLAG(`${f} ${val} must never appear in a sandbox argv`)
      }
    }
  }
  return argv
}

// The minimal host environment the *client* process (podman / systemd-run) needs in order to
// work at all. This exists because of invariant 2: we never inherit the caller's environment, so
// anything genuinely required has to be named here and justified.
//
// systemd-run --user talks to the user's session bus, and without these two it fails with
// "Failed to connect to user scope bus via local transport: $DBUS_SESSION_BUS_ADDRESS and
// $XDG_RUNTIME_DIR not defined" -- found by the integration test skipping rather than passing.
// Note none of this reaches the workload: the sandbox env is the separate allowlist built above.
function requiredHostEnv(spec, hostEnv) {
  const src = hostEnv || {}
  const out = { PATH: src.PATH || '/usr/local/bin:/usr/bin:/bin' }
  if (spec.scope !== false) {
    for (const k of ['DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR']) {
      if (src[k]) out[k] = src[k]
    }
  }
  // Rootless podman needs a home to find its own storage config.
  if (src.HOME) out.HOME = src.HOME
  if (src.XDG_CONFIG_HOME) out.XDG_CONFIG_HOME = src.XDG_CONFIG_HOME
  return out
}

function build(spec) {
  assertSpec(spec)
  const pod = podmanArgs(spec)
  assertSafe(pod)

  const useScope = spec.scope !== false
  const program = useScope ? 'systemd-run' : 'podman'
  const args = useScope ? [...scopeArgs(spec), '--', 'podman', ...pod] : pod

  return {
    program,
    args,
    argv: [program, ...args],
    podmanArgs: pod,
    tier: spec.tier
  }
}

module.exports = {
  build,
  assertSafe,
  requiredHostEnv,
  podmanArgs,
  resolveLimits,
  scopeArgs,
  FORBIDDEN,
  FORBIDDEN_VALUES,
  TIERS,
  DEFAULTS
}
