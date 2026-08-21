'use strict'

// Seccomp profile generator.
//
// Defense-in-depth on top of --cap-drop=ALL, not a substitute for it. Measured on this host, the
// distinction matters and is easy to get backwards:
//
//   podman defaults (no cap-drop):  unshare -Ur  ->  uid=0, CapEff: 000001ffffffffff
//   --cap-drop ALL:                 unshare -Ur  ->  write failed /proc/self/uid_map: EPERM
//
// So the classic "unshare grants you root in a fresh userns" path is already closed by cap-drop
// (writing uid_map needs CAP_SETUID in the *parent* namespace, and cap-drop empties the bounding
// set). What this profile buys is removal of reachable kernel code: several userns/mount LPEs are
// reachable WITHOUT capabilities, so taking mount/pivot_root/keyctl/ptrace/bpf out of the syscall
// surface is worth doing on its own terms.
//
// The base profile that ships with podman is not a boundary: /usr/share/containers/seccomp.json
// lists unshare, clone, clone3, mount, umount2, pivot_root, keyctl, ptrace and mknod as
// SCMP_ACT_ALLOW with no argument filter and no capability gate, and the upstream docker
// clone-arg-mask rule is absent entirely.
//
// We generate by REWRITING the base document -- stripping the overridden names out of its allow
// rules before appending our own -- rather than by appending and relying on libseccomp's
// resolution order. Output is key-sorted so the committed profile diffs cleanly and any
// weakening is visible in review.

const WorkflowError = require('../../errors.js')

const BASE_PATH = '/usr/share/containers/seccomp.json'

// Forced to EPERM regardless of capabilities.
const DENY = [
  // namespace + mount surface
  'unshare',
  'setns',
  'mount',
  'umount',
  'umount2',
  'pivot_root',
  'chroot',
  'move_mount',
  'open_tree',
  'fsopen',
  'fsconfig',
  'fsmount',
  'fspick',
  'mount_setattr',
  // kernel keyring
  'keyctl',
  'add_key',
  'request_key',
  // cross-process inspection
  'ptrace',
  'process_vm_readv',
  'process_vm_writev',
  'pidfd_getfd',
  'kcmp',
  // kernel programmability / observability
  'bpf',
  'perf_event_open',
  'syslog',
  // filesystem handles (open_by_handle_at is a classic container escape primitive)
  'name_to_handle_at',
  'open_by_handle_at',
  // device nodes
  'mknod',
  'mknodat',
  // modules
  'init_module',
  'finit_module',
  'delete_module',
  // machine state
  'reboot',
  'kexec_load',
  'kexec_file_load',
  'swapon',
  'swapoff',
  'acct',
  'vhangup',
  // clock
  'settimeofday',
  'clock_settime',
  'clock_adjtime',
  'adjtimex',
  // quota + io ports
  'quotactl',
  'quotactl_fd',
  'ioperm',
  'iopl',
  // async io / fault handling: large exploited surface, no legitimate build use
  'io_uring_setup',
  'io_uring_enter',
  'io_uring_register',
  'userfaultfd'
]

// Syscalls a real toolchain needs that we must NOT block. Asserted by test, in both directions:
// over-blocking these breaks cmake/ninja/node-gyp in ways that look like mysterious hangs.
const KEEP = [
  'memfd_create',
  'seccomp',
  'landlock_create_ruleset',
  'landlock_add_rule',
  'landlock_restrict_self'
]

// CLONE_NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET
const CLONE_NS_MASK = 0x7e020000

const ENOSYS = 38
const EPERM = 1

function loadBase(fs, path = BASE_PATH) {
  let raw
  try {
    raw = fs.readFileSync(path, 'utf8')
  } catch {
    throw WorkflowError.SECCOMP_BASE_MISSING(
      `cannot read base seccomp profile at ${path}; install the containers-common package`
    )
  }
  let doc
  try {
    doc = JSON.parse(raw)
  } catch (err) {
    throw WorkflowError.SECCOMP_INVALID(`base profile at ${path} is not valid JSON: ${err.message}`)
  }
  return assertBase(doc)
}

function assertBase(doc) {
  if (!doc || typeof doc !== 'object') {
    throw WorkflowError.SECCOMP_INVALID('base profile must be an object')
  }
  if (doc.defaultAction !== 'SCMP_ACT_ERRNO') {
    throw WorkflowError.SECCOMP_INVALID(
      `base profile defaultAction must be SCMP_ACT_ERRNO (default-deny), got ${doc.defaultAction}`
    )
  }
  if (!Array.isArray(doc.syscalls)) {
    throw WorkflowError.SECCOMP_INVALID('base profile has no syscalls array')
  }
  return doc
}

function generate(opts = {}) {
  const base = opts.base
    ? assertBase(opts.base)
    : loadBase(opts.fs || require('bare-fs'), opts.basePath)

  const nested = opts.allowNestedNamespaces === true
  const ptrace = opts.allowPtrace === true

  // Escape hatches are SUBTRACTIVE: they remove names from *our* deny list. Whether a syscall
  // then becomes callable still depends on the base profile, because the base is default-deny --
  // so relaxing a name the base itself denies changes nothing. Verified against the shipped base:
  // unshare/mount/umount2/pivot_root are ALLOWed there (so the hatch works), but `setns` is
  // ERRNO in the base regardless, which is why it is not listed here.
  const deny = new Set(DENY)
  if (nested) for (const n of ['unshare', 'mount', 'umount2', 'pivot_root']) deny.delete(n)
  if (ptrace) for (const n of ['ptrace', 'process_vm_readv', 'process_vm_writev']) deny.delete(n)

  // clone/clone3/personality get argument rules rather than a flat deny, so they are handled
  // separately and must not be left behind in a base allow rule either.
  const rewritten = new Set([...deny, 'clone', 'clone3', 'personality'])

  const syscalls = []
  for (const rule of base.syscalls) {
    const names = (rule.names || []).filter((n) => !rewritten.has(n))
    if (names.length === 0) continue
    syscalls.push({ ...rule, names: names.sort() })
  }

  // Explicit denies.
  const denied = [...deny].sort()
  if (denied.length) {
    syscalls.push({ names: denied, action: 'SCMP_ACT_ERRNO', errnoRet: EPERM })
  }

  if (!nested) {
    // Allow clone ONLY when it requests no new namespace. Masked-equal against 0 means "none of
    // these flag bits set".
    syscalls.push({
      names: ['clone'],
      action: 'SCMP_ACT_ALLOW',
      args: [{ index: 0, value: CLONE_NS_MASK, valueTwo: 0, op: 'SCMP_CMP_MASKED_EQ' }]
    })
    // clone3 passes its flags in a userspace struct, which seccomp cannot dereference -- so it
    // cannot be filtered, only refused. Return ENOSYS, NOT EPERM: glibc/musl treat ENOSYS as
    // "kernel too old" and fall back to clone(), which IS filtered above. Returning EPERM here
    // breaks pthread_create and presents as "npm hangs forever".
    syscalls.push({ names: ['clone3'], action: 'SCMP_ACT_ERRNO', errnoRet: ENOSYS })
  } else {
    syscalls.push({ names: ['clone', 'clone3'], action: 'SCMP_ACT_ALLOW' })
  }

  // Only the sane personalities; blocks turning off ASLR among other things.
  for (const value of [0x0, 0x8, 0x20000, 0x20008, 0xffffffff]) {
    syscalls.push({
      names: ['personality'],
      action: 'SCMP_ACT_ALLOW',
      args: [{ index: 0, value, op: 'SCMP_CMP_EQ' }]
    })
  }

  return {
    defaultAction: 'SCMP_ACT_ERRNO',
    defaultErrnoRet: EPERM,
    architectures: base.architectures || ['SCMP_ARCH_X86_64', 'SCMP_ARCH_X86', 'SCMP_ARCH_X32'],
    syscalls
  }
}

// Stable, sorted serialization so the committed profile produces clean diffs.
function serialize(profile) {
  return JSON.stringify(profile, null, 2) + '\n'
}

// Does the profile actually deny `name`? Used by tests and by a startup self-check, so a
// hand-edit of the committed profile cannot silently weaken it.
function effectiveAction(profile, name) {
  let action = profile.defaultAction
  let errnoRet = profile.defaultErrnoRet
  let args = null
  for (const rule of profile.syscalls) {
    if (!rule.names.includes(name)) continue
    action = rule.action
    errnoRet = rule.errnoRet
    // The base profile writes `args: []` rather than omitting it, and [] is truthy -- normalize
    // so "has an argument filter" is a question callers can actually ask.
    args = rule.args && rule.args.length ? rule.args : null
  }
  return { action, errnoRet, args }
}

module.exports = {
  generate,
  serialize,
  effectiveAction,
  loadBase,
  assertBase,
  DENY,
  KEEP,
  BASE_PATH,
  CLONE_NS_MASK,
  ENOSYS
}
