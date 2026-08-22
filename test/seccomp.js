'use strict'

// Unit tests for the seccomp profile generator.
//
// The logic tests use an injected fake base document so they are deterministic and do not depend
// on the host's containers-common package. A second group runs against the real base profile and
// skips cleanly when it is absent.
//
// The single most important assertion in this file is `clone3 -> ENOSYS`. Returning EPERM there
// instead breaks pthread_create on modern glibc and presents as "npm hangs forever" -- validated
// against real Node worker_threads before this test was written.

const test = require('brittle')
const fs = require('bare-fs')
const os = require('bare-os')
const { spawnSync } = require('bare-subprocess')
const seccomp = require('../lib/isolation/podman/seccomp.js')
const { hostEnv, which } = require('../lib/host-env.js')

const PINNED_BASE = 'etc/seccomp/base-v1.json'

// A miniature stand-in for /usr/share/containers/seccomp.json that reproduces the trait we care
// about: the namespace syscalls sitting in an unconditional allow rule.
// Mirrors the shipped profile's actual shape (verified by reading it): one huge unconditional
// allow rule covering the namespace syscalls, cap-gated rules for bpf, and `setns` denied
// outright. A fake that is more restrictive than reality produces failures that look like code
// bugs but are only artifacts of the fixture.
const FAKE_BASE = {
  defaultAction: 'SCMP_ACT_ERRNO',
  architectures: ['SCMP_ARCH_X86_64'],
  syscalls: [
    {
      names: [
        'read',
        'write',
        'openat',
        'personality',
        'memfd_create',
        'seccomp',
        'landlock_create_ruleset',
        'landlock_add_rule',
        'landlock_restrict_self',
        'unshare',
        'clone',
        'clone3',
        'mount',
        'umount2',
        'pivot_root',
        'ptrace',
        'process_vm_readv',
        'process_vm_writev',
        'keyctl',
        'mknod'
      ],
      action: 'SCMP_ACT_ALLOW'
    },
    { names: ['bpf'], action: 'SCMP_ACT_ALLOW', includes: { caps: ['CAP_SYS_ADMIN'] } },
    { names: ['bpf'], action: 'SCMP_ACT_ERRNO', errnoRet: 1 },
    // setns is ERRNO in the shipped base regardless of our profile.
    { names: ['setns'], action: 'SCMP_ACT_ERRNO', errnoRet: 1 }
  ]
}

const gen = (opts) => seccomp.generate({ base: FAKE_BASE, ...opts })
const act = (p, n) => seccomp.effectiveAction(p, n)

test('default-deny is preserved', (t) => {
  const p = gen()
  t.is(p.defaultAction, 'SCMP_ACT_ERRNO')
  t.is(p.defaultErrnoRet, 1)
})

test('every denied syscall resolves to EPERM', (t) => {
  const p = gen()
  for (const name of seccomp.DENY) {
    const e = act(p, name)
    t.is(e.action, 'SCMP_ACT_ERRNO', name + ' is denied')
    t.is(e.errnoRet, 1, name + ' returns EPERM')
  }
})

test('clone3 returns ENOSYS, not EPERM', (t) => {
  // seccomp cannot inspect clone3's flags (they live in a userspace struct), so it can only be
  // refused. ENOSYS makes glibc/musl fall back to clone(), which IS filtered. EPERM would break
  // threading instead.
  const e = act(gen(), 'clone3')
  t.is(e.action, 'SCMP_ACT_ERRNO')
  t.is(e.errnoRet, 38, 'ENOSYS == 38, so libc falls back to the filtered clone()')
  t.not(e.errnoRet, 1, 'EPERM here would break pthread_create')
})

test('clone is allowed only with no new namespace', (t) => {
  const e = act(gen(), 'clone')
  t.is(e.action, 'SCMP_ACT_ALLOW')
  t.ok(e.args && e.args.length === 1)
  t.is(e.args[0].op, 'SCMP_CMP_MASKED_EQ')
  t.is(e.args[0].index, 0)
  t.is(e.args[0].value, seccomp.CLONE_NS_MASK)
  t.is(e.args[0].valueTwo, 0, 'masked-equal zero == none of the CLONE_NEW* bits set')
})

test('toolchain syscalls are NOT over-blocked', (t) => {
  // The other direction of the same risk: blocking these looks like a mysterious build failure.
  const p = gen()
  for (const name of seccomp.KEEP) {
    t.not(act(p, name).action, 'SCMP_ACT_ERRNO', name + ' must stay available')
  }
})

test('overridden names are stripped from base allow rules, not just shadowed', (t) => {
  const p = gen()
  for (const rule of p.syscalls) {
    if (rule.action !== 'SCMP_ACT_ALLOW' || rule.args) continue
    for (const n of ['unshare', 'mount', 'ptrace', 'clone3']) {
      t.absent(rule.names.includes(n), n + ' left in a blanket allow rule')
    }
  }
})

test('benign base syscalls survive', (t) => {
  const p = gen()
  for (const n of ['read', 'write', 'openat']) t.is(act(p, n).action, 'SCMP_ACT_ALLOW', n)
})

test('nestedNamespaces escape hatch relaxes exactly the namespace set', (t) => {
  // The hatch is subtractive: it removes names from OUR deny list, and the base decides the rest.
  const p = gen({ allowNestedNamespaces: true })
  for (const n of ['unshare', 'mount', 'umount2', 'pivot_root']) {
    t.not(act(p, n).action, 'SCMP_ACT_ERRNO', n + ' relaxed')
  }
  t.is(
    act(p, 'setns').action,
    'SCMP_ACT_ERRNO',
    'setns stays denied -- the base denies it, hatch or not'
  )
  t.is(act(p, 'clone3').action, 'SCMP_ACT_ALLOW', 'clone3 allowed when namespaces are permitted')
  t.is(act(p, 'keyctl').action, 'SCMP_ACT_ERRNO', 'unrelated denies stay denied')
  t.is(act(p, 'bpf').action, 'SCMP_ACT_ERRNO', 'bpf stays denied')
})

test('ptrace escape hatch is independent', (t) => {
  const p = gen({ allowPtrace: true })
  for (const n of ['ptrace', 'process_vm_readv', 'process_vm_writev']) {
    t.not(act(p, n).action, 'SCMP_ACT_ERRNO', n + ' relaxed')
  }
  t.is(act(p, 'unshare').action, 'SCMP_ACT_ERRNO', 'namespaces stay denied')
})

test('a bad base document is rejected loudly', (t) => {
  t.exception(
    () => seccomp.generate({ base: { defaultAction: 'SCMP_ACT_ALLOW', syscalls: [] } }),
    /SECCOMP_INVALID/,
    'a default-allow base is not a boundary'
  )
  t.exception(
    () => seccomp.generate({ base: { defaultAction: 'SCMP_ACT_ERRNO' } }),
    /SECCOMP_INVALID/
  )
})

test('serialization is deterministic', (t) => {
  t.is(seccomp.serialize(gen()), seccomp.serialize(gen()), 'stable output keeps diffs reviewable')
  t.ok(seccomp.serialize(gen()).endsWith('\n'))
})

// The real base profile, wherever it actually lives.
//
// `/usr/share/containers/seccomp.json` is a path on the machine that RUNS containers. On Linux that
// is this host. On macOS and Windows podman is a remote client and the file lives inside the
// podman-machine VM, so both tests below skipped -- and the second one is the **drift guard**, which
// is what stops a committed profile diverging from the generator. Silently skipping it means a
// Mac-only developer can commit a drifted security profile and nothing notices. So: try the host,
// then ask the machine.
function loadRealBase() {
  try {
    return seccomp.loadBase(fs)
  } catch {}
  if (os.platform() === 'linux') return null
  // `podman machine ssh cat` rather than a bind mount: read-only, needs no container, and works
  // whether or not any image has been built.
  const bin = which('podman')
  if (!bin) return null
  const r = spawnSync('podman', ['machine', 'ssh', 'cat /usr/share/containers/seccomp.json'], {
    env: hostEnv()
  })
  if (r.status !== 0 || !r.stdout) return null
  try {
    return seccomp.assertBase(JSON.parse(r.stdout.toString()))
  } catch {
    return null
  }
}

// --- against the real host profile ------------------------------------------------------

test('the real base profile has the weakness this generator exists to fix', (t) => {
  const base = loadRealBase()
  if (!base) {
    t.comment('no base profile on this host and none reachable via podman machine; skipping')
    t.pass('skipped')
    return
  }
  const before = seccomp.effectiveAction(base, 'unshare')
  t.is(before.action, 'SCMP_ACT_ALLOW', 'base allows unshare unconditionally')
  // The base writes `args: []`; effectiveAction normalizes that empty array to null so this
  // reads as the question we actually mean.
  t.absent(before.args, 'with no argument filter and no capability gate')

  const after = seccomp.effectiveAction(seccomp.generate({ base }), 'unshare')
  t.is(after.action, 'SCMP_ACT_ERRNO', 'and we deny it')
})

test('the committed profile matches the generator (drift guard)', (t) => {
  // Against the PINNED base (etc/seccomp/base-v1.json), never the live one.
  //
  // This used to generate from whatever containers-common the local machine shipped, which made the
  // assertion a function of your distro rather than of our code. Measured across 448 syscalls
  // between an Arch host and the Fedora CoreOS guest in a macOS podman machine, 6 disagreed -- and
  // not harmlessly: the Arch base denies `socket(AF_VSOCK)` and the CoreOS one does not, and the
  // CoreOS base omits the futex_* family so it would fall through to a default EPERM. Generating on
  // the "wrong" machine would therefore have quietly weakened the host<->guest boundary and risked
  // the same threading breakage the clone3 -> ENOSYS assertion exists to prevent.
  //
  // Pinning makes this test mean "someone changed the generator without regenerating", which is the
  // only thing it was ever meant to catch. Adopting a new upstream base is a deliberate, reviewable
  // act: bare scripts/build/seccomp.js --capture.
  let base
  try {
    base = seccomp.assertBase(JSON.parse(fs.readFileSync(PINNED_BASE, 'utf8')))
  } catch {
    t.comment(`no pinned base at ${PINNED_BASE}; skipping`)
    t.comment('capture one on the machine whose base produced the committed profile:')
    t.comment('  bare scripts/build/seccomp.js --capture')
    t.pass('skipped')
    return
  }
  let committed
  try {
    committed = fs.readFileSync('etc/seccomp/build-v1.json', 'utf8')
  } catch {
    t.comment('committed profile unavailable; skipping')
    t.pass('skipped')
    return
  }
  t.is(
    committed,
    seccomp.serialize(seccomp.generate({ base })),
    'regenerate and commit when this fails: bare scripts/build/seccomp.js'
  )
})

test('the pinned base is what the committed profile was actually built from', (t) => {
  // A pin that does not match the output is worse than no pin: the drift guard above would fail for
  // a reason nobody can act on. Kept separate so the failure says which of the two is wrong.
  let base
  try {
    base = seccomp.assertBase(JSON.parse(fs.readFileSync(PINNED_BASE, 'utf8')))
  } catch {
    t.comment(`no pinned base at ${PINNED_BASE}; skipping`)
    return t.pass('skipped')
  }
  const live = loadRealBase()
  if (!live) return t.pass('no live base to compare against')

  // Not an equality assertion -- the live base legitimately differs by distro. This reports the
  // difference so a surprising drift-guard failure has its cause visible in the same run.
  const namesOf = (d) => new Set(d.syscalls.flatMap((x) => x.names))
  const pinned = namesOf(base)
  const current = namesOf(live)
  const onlyLive = [...current].filter((x) => !pinned.has(x))
  const onlyPinned = [...pinned].filter((x) => !current.has(x))
  if (onlyLive.length || onlyPinned.length) {
    t.comment(`this host's base differs from the pin -- that is expected across distros`)
    t.comment(`  only in this host's base: ${onlyLive.slice(0, 8).join(', ') || '(none)'}`)
    t.comment(`  only in the pinned base:  ${onlyPinned.slice(0, 8).join(', ') || '(none)'}`)
  }
  t.pass('pin and live base compared')
})
