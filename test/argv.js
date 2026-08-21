'use strict'

// Unit tests for the argv builder. No containers, no podman, no filesystem -- the builder is a
// pure function, which is the whole reason the isolation posture is cheap to test.
//
// The two tests that earn their keep here are the forbidden-flag table (a spec that would weaken
// the sandbox must throw, not warn) and the full-argv snapshot (any accidental weakening becomes
// a reviewable diff in a PR).

const test = require('brittle')
const argv = require('../lib/isolation/podman/argv.js')

const DIGEST = 'sha256:' + 'a'.repeat(64)

function spec(extra = {}) {
  return {
    jobId: 'job1',
    tier: 'container',
    image: { ref: 'localhost/bw-base', digest: DIGEST },
    scope: false,
    ...extra
  }
}

function flagValue(args, flag) {
  const out = []
  for (let i = 0; i < args.length; i++) if (args[i] === flag) out.push(args[i + 1])
  return out
}

test('builds a container-tier argv', (t) => {
  const r = argv.build(spec())
  t.is(r.program, 'podman', 'no systemd scope when scope:false')
  t.is(r.args[0], 'run')
  t.ok(r.args.includes('--rm'), 'container is removed on exit')
  t.alike(flagValue(r.args, '--name'), ['bw-job1'], 'name is derived from jobId')
})

test('microvm tier selects krun by annotation, not --runtime', (t) => {
  const r = argv.build(spec({ tier: 'microvm' }))
  t.alike(flagValue(r.args, '--annotation'), ['run.oci.handler=krun'], 'krun via annotation')
  t.absent(
    r.args.includes('--runtime'),
    'crun selects the microVM path by annotation; --runtime krun is wrong'
  )
  t.alike(flagValue(r.args, '--device'), ['/dev/kvm'], 'VMM needs /dev/kvm on the host side')
})

test('container tier does not request kvm', (t) => {
  const r = argv.build(spec())
  t.absent(r.args.includes('--annotation'))
  t.absent(r.args.includes('--device'))
})

test('the hardening flags are all present', (t) => {
  const r = argv.build(spec())
  const a = r.args
  t.alike(
    flagValue(a, '--cap-drop'),
    ['ALL'],
    'cap-drop ALL is the flag actually blocking nested-userns escalation'
  )
  t.alike(flagValue(a, '--userns'), ['auto:size=1024'], 'host uid deliberately unmapped')
  t.alike(flagValue(a, '--network'), ['none'], 'default deny egress')
  t.ok(a.includes('--read-only'), 'immutable rootfs')
  t.ok(
    a.includes('--read-only-tmpfs=false'),
    'podman would otherwise hand back rw /dev,/run,/tmp,/var/tmp silently'
  )
  t.ok(a.includes('--no-hosts'))
  t.ok(a.includes('--security-opt') && a.includes('no-new-privileges'))
  t.alike(flagValue(a, '--pids-limit'), ['512'])
  t.alike(flagValue(a, '--pull'), ['never'], 'never pull at run time')
  t.alike(
    flagValue(a, '--log-driver'),
    ['none'],
    'an untrusted build must not fill the host journal'
  )
  t.alike(flagValue(a, '--user'), ['1000:1000'], 'not container-root even inside the userns')
})

test('--workdir is the workspace root, not the src dir', (t) => {
  // podman creates the workdir as root before dropping to --user, so naming /w/src here yields a
  // root-owned dir the step cannot write to -- with `pwd` still working, which hides it. Measured:
  //   --workdir /w/src  ->  /w/src root:root 755, touch fails
  //   --workdir /w      ->  /w/src ubuntu:ubuntu 755, touch works
  const r = argv.build(spec())
  const i = r.args.indexOf('--workdir')
  t.is(r.args[i + 1], '/w', 'the agent creates src/ itself, as the step uid')
})

test('--dns=none is never emitted (podman rejects it with --network none)', (t) => {
  // Measured: "Error: conflicting options: dns and the network mode: none". With no network there
  // is no resolver to disable, so the flag is redundant AND fatal.
  const r = argv.build(spec())
  t.absent(
    r.args.some((x) => x === '--dns' || x.startsWith('--dns=')),
    'no --dns flag at all'
  )
})

test('workspace is a size-capped tmpfs, not an unbounded volume', (t) => {
  const r = argv.build(spec())
  const mounts = flagValue(r.args, '--mount')
  const ws = mounts.find((m) => m.includes('dst=/w'))
  t.ok(ws, 'workspace mount exists')
  t.ok(ws.startsWith('type=tmpfs'), 'tmpfs, because podman volumes on overlay have NO size limit')
  t.ok(/tmpfs-size=\d+/.test(ws), 'and it is capped')
  // Without this the step cannot write to its own workspace: a tmpfs mounts root:root 0755 no
  // matter what the image chowned, because the mount covers it.
  t.ok(ws.includes('tmpfs-mode=1777'), 'and writable by the step uid')
  t.ok(ws.includes('nosuid') && ws.includes('nodev'))
})

test('/tmp is writable and exec-able, /run is noexec', (t) => {
  const r = argv.build(spec())
  const tmpfs = flagValue(r.args, '--tmpfs')
  const tmp = tmpfs.find((m) => m.startsWith('/tmp:'))
  const run = tmpfs.find((m) => m.startsWith('/run:'))
  // cmake/ninja/node-gyp exec out of temp dirs; noexec breaks real builds and is defeated by
  // memfd_create anyway, so it buys nothing here.
  t.absent(tmp.includes('noexec'), '/tmp must stay exec-able for real toolchains')
  t.ok(tmp.includes('nosuid') && tmp.includes('nodev'))
  t.ok(run.includes('noexec'), '/run gains noexec for free')
})

test('swap is disabled by pinning memory-swap to memory', (t) => {
  // A coherent tiny spec rather than `memoryBytes: 1024`: the tmpfs mounts are charged to the same
  // cgroup, so the limits are only meaningful together and resolveLimits() now says so.
  const tiny = {
    memoryBytes: 256 * 1024 * 1024,
    workspaceBytes: 64 * 1024 * 1024,
    tmpBytes: 32 * 1024 * 1024,
    shmBytes: 8 * 1024 * 1024,
    headroomBytes: 32 * 1024 * 1024
  }
  const r = argv.build(spec({ limits: tiny }))
  t.alike(flagValue(r.args, '--memory'), ['268435456b'])
  t.alike(flagValue(r.args, '--memory-swap'), ['268435456b'], 'swap pinned to the same value')
})

test('env is an explicit allowlist and is sorted', (t) => {
  const r = argv.build(spec({ env: { ZZZ: '1', AAA: '2' } }))
  const envs = flagValue(r.args, '--env')
  t.alike(
    envs,
    [
      'AAA=2',
      'BW_JOB=job1',
      'BW_WORKSPACE=/w',
      'CI=true',
      'HOME=/w/home',
      'PATH=/usr/local/bin:/usr/bin:/bin',
      'TMPDIR=/tmp',
      'ZZZ=1'
    ],
    'deterministic ordering keeps the argv snapshot stable'
  )
})

test('systemd scope carries the CPU limit, because --cpus is inert here', (t) => {
  // podman reports CgroupControllers=[memory pids] from a login session, so --cpus silently does
  // nothing. systemd-run makes the controllers available on the intermediate slices.
  const r = argv.build(spec({ scope: true, limits: { cpuQuota: 2.5 } }))
  t.is(r.program, 'systemd-run')
  t.ok(r.args.includes('CPUQuota=250%'))
  t.ok(r.args.includes('--user') && r.args.includes('--scope'))
  t.ok(r.args.includes('--'), 'podman is separated from the scope args')
  t.absent(r.podmanArgs.includes('--cpus'), 'never emit the inert flag')
})

test('podman and systemd byte syntax do not get crossed', (t) => {
  // systemd rejects podman's 'b' suffix: "Failed to parse MemoryMax= value '4294967296b'".
  // Found by running the argv, not by reading it -- hence a regression test.
  const r = argv.build(spec({ scope: true, limits: { memoryBytes: 8589934592 } }))
  t.ok(r.podmanArgs.includes('8589934592b'), 'podman takes the b suffix')
  const mem = r.args.find((x) => typeof x === 'string' && x.startsWith('MemoryMax='))
  t.is(mem, 'MemoryMax=8589934592', 'systemd takes a bare integer')
  t.absent(mem.endsWith('b'), 'a b suffix here is fatal at runtime')
  t.ok(r.args.includes('MemorySwapMax=0'), 'swap off at the scope level too')
})

test('requiredHostEnv is an allowlist, never the ambient environment', (t) => {
  const host = {
    PATH: '/usr/bin',
    HOME: '/home/ryan',
    XDG_RUNTIME_DIR: '/run/user/1000',
    DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/1000/bus',
    GH_TOKEN: 'ghp_secret',
    NODE_AUTH_TOKEN: 'npm_secret',
    AWS_SECRET_ACCESS_KEY: 'aws_secret'
  }
  const scoped = argv.requiredHostEnv(spec({ scope: true }), host)
  t.absent('GH_TOKEN' in scoped, 'secrets never reach even the podman client')
  t.absent('NODE_AUTH_TOKEN' in scoped)
  t.absent('AWS_SECRET_ACCESS_KEY' in scoped)
  // systemd-run --user cannot reach the session bus without these two.
  t.is(scoped.XDG_RUNTIME_DIR, '/run/user/1000')
  t.is(scoped.DBUS_SESSION_BUS_ADDRESS, 'unix:path=/run/user/1000/bus')

  const plain = argv.requiredHostEnv(spec({ scope: false }), host)
  t.absent('DBUS_SESSION_BUS_ADDRESS' in plain, 'not needed without a systemd scope')
  t.is(plain.PATH, '/usr/bin')
})

test('timeout ladder: systemd outlives podman so we can tell which fired', (t) => {
  const r = argv.build(spec({ scope: true, limits: { wallClockMs: 60000 } }))
  t.alike(flagValue(r.podmanArgs, '--timeout'), ['60'])
  t.ok(r.args.includes('RuntimeMaxSec=360'))
})

// --- the invariants ---------------------------------------------------------------------

test('host bind mounts are refused structurally', (t) => {
  for (const m of [
    { type: 'bind', src: '/home/ryan', dst: '/w' },
    { hostPath: '/etc' },
    { src: '/tmp' }
  ]) {
    t.exception(() => argv.build(spec({ mounts: [m] })), /HOST_MOUNT_REFUSED/, JSON.stringify(m))
  }
})

test('unpinned images are refused', (t) => {
  t.exception(
    () => argv.build(spec({ image: { ref: 'ubuntu', digest: undefined } })),
    /IMAGE_NOT_PINNED/
  )
  t.exception(
    () => argv.build(spec({ image: { ref: 'ubuntu', digest: 'latest' } })),
    /IMAGE_NOT_PINNED/
  )
  t.exception(
    () => argv.build(spec({ image: { ref: 'ubuntu', digest: 'sha256:xyz' } })),
    /IMAGE_NOT_PINNED/
  )
})

test('bad specs are rejected', (t) => {
  t.exception(
    () => argv.build(spec({ jobId: 'Bad Id' })),
    /INVALID_SPEC/,
    'jobId is used in a container name'
  )
  t.exception(() => argv.build(spec({ jobId: '../escape' })), /INVALID_SPEC/)
  t.exception(
    () => argv.build(spec({ tier: 'emulation' })),
    /UNKNOWN_TIER/,
    'emulation is not a tier and never will be'
  )
  t.exception(() => argv.build(spec({ tier: 'host' })), /UNKNOWN_TIER/)
  t.exception(() => argv.build(spec({ network: { mode: 'full' } })), /INVALID_SPEC/)
  t.exception(() => argv.build(spec({ env: { 'no-dashes': 'x' } })), /INVALID_SPEC/)
  t.exception(() => argv.build(spec({ env: { OK: 5 } })), /INVALID_SPEC/)
})

test('assertSafe rejects every forbidden flag', (t) => {
  const bad = [
    ['--privileged'],
    ['--env-host'],
    ['--volumes-from', 'other'],
    ['-v', '/home/ryan:/w'],
    ['--volume', '/etc:/etc'],
    ['--cap-add', 'SYS_ADMIN'],
    ['--group-add', 'keep-groups'],
    ['-p', '8080:80'],
    ['--publish', '8080:80'],
    ['--uidmap', '0:1000:1'],
    ['--network', 'host'],
    ['--network=host'],
    ['--pid', 'host'],
    ['--ipc', 'host'],
    ['--uts', 'host'],
    ['--cgroupns', 'host'],
    ['--userns', 'host'],
    ['--userns', 'keep-id'],
    ['--userns', 'nomap'],
    ['--security-opt', 'seccomp=unconfined'],
    ['--security-opt', 'label=disable'],
    ['--security-opt', 'unmask=/proc'],
    ['--mount', 'type=bind,src=/home,dst=/w'],
    ['--device', '/dev/sda']
  ]
  for (const args of bad) {
    t.exception(() => argv.assertSafe(['run', ...args]), /FORBIDDEN_FLAG/, args.join(' '))
  }
})

test('assertSafe passes a real generated argv', (t) => {
  t.execution(() => argv.assertSafe(argv.build(spec()).podmanArgs))
  t.execution(() => argv.assertSafe(argv.build(spec({ tier: 'microvm' })).podmanArgs))
  // /dev/kvm is the one permitted device, and only because the host-side VMM needs it.
  t.execution(() => argv.assertSafe(['run', '--device', '/dev/kvm']))
})

// --- snapshot --------------------------------------------------------------------------

test('full argv snapshot (container tier)', (t) => {
  const r = argv.build(spec())
  const expected = [
    'run',
    '--rm',
    '--name',
    'bw-job1',
    '--pull',
    'never',
    '--log-driver',
    'none',
    '-i',
    '--hostname',
    'sandbox',
    '--userns',
    'auto:size=1024',
    '--user',
    '1000:1000',
    '--pid',
    'private',
    '--ipc',
    'private',
    '--uts',
    'private',
    '--cgroupns',
    'private',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--security-opt',
    'proc-opts=nosuid,nodev,noexec,hidepid=2',
    '--security-opt',
    'mask=/proc/scsi:/sys/firmware:/sys/devices/virtual/powercap:/proc/kcore:/proc/keys',
    '--umask',
    '0022',
    '--read-only',
    '--read-only-tmpfs=false',
    '--mount',
    'type=tmpfs,dst=/w,tmpfs-size=4294967296,tmpfs-mode=1777,nosuid,nodev',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,size=1073741824,mode=1777',
    '--tmpfs',
    '/run:rw,nosuid,nodev,noexec,size=16m,mode=0755',
    '--shm-size',
    '67108864b',
    '--network',
    'none',
    '--no-hosts',
    '--memory',
    '8589934592b',
    '--memory-swap',
    '8589934592b',
    '--pids-limit',
    '512',
    '--ulimit',
    'nofile=65536:65536',
    '--ulimit',
    'nproc=512:512',
    '--ulimit',
    'core=0:0',
    '--timeout',
    '3600',
    '--workdir',
    '/w',
    '--env',
    'BW_JOB=job1',
    '--env',
    'BW_WORKSPACE=/w',
    '--env',
    'CI=true',
    '--env',
    'HOME=/w/home',
    '--env',
    'PATH=/usr/local/bin:/usr/bin:/bin',
    '--env',
    'TMPDIR=/tmp',
    '--entrypoint',
    '/opt/bw/agent',
    'localhost/bw-base@' + DIGEST
  ]
  t.alike(r.args, expected, 'any diff here is a deliberate change to the isolation posture')
})

test('tmpfs sizes and the memory limit are checked against each other', (t) => {
  // Measured, and the reason this check exists: 1500 MiB written into a 4 GiB tmpfs under
  // `--memory 1g` is OOM-KILLED at ~1020 MiB. It does not get ENOSPC. So `tmpfs-size` is an upper
  // bound the memory cgroup can make unreachable, and a spec that promises more workspace than
  // memory is promising a SIGKILL instead of a disk-full error -- a much worse thing to debug.
  t.ok(argv.resolveLimits({}), 'the shipped defaults are coherent')

  try {
    argv.resolveLimits({ limits: { workspaceBytes: 64 * 1024 * 1024 * 1024 } })
    t.fail('an unreachable workspace cap should be refused')
  } catch (err) {
    t.is(err.code, 'INVALID_SPEC')
    t.ok(/can never be reached/.test(err.message))
    t.ok(/OOM-kill \(exit 137\) rather than ENOSPC/.test(err.message), 'and says what would happen')
  }

  // The footgun the check is really for: overriding ONE tmpfs size and inheriting the others.
  try {
    argv.resolveLimits({
      limits: { workspaceBytes: 32 * 1024 * 1024, memoryBytes: 128 * 1024 * 1024 }
    })
    t.fail('inheriting a 1 GiB /tmp under a 128 MiB memory cap should be refused')
  } catch (err) {
    t.is(err.code, 'INVALID_SPEC', 'shrinking the workspace alone is not enough')
  }

  const small = argv.resolveLimits({
    limits: {
      workspaceBytes: 32 * 1024 * 1024,
      tmpBytes: 32 * 1024 * 1024,
      shmBytes: 8 * 1024 * 1024,
      headroomBytes: 64 * 1024 * 1024,
      memoryBytes: 512 * 1024 * 1024
    }
  })
  t.is(small.workspaceBytes, 32 * 1024 * 1024, 'a coherent small spec is accepted')
})
