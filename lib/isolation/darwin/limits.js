'use strict'

// Resource limits for the native darwin tier, and -- just as importantly -- an explicit record of the
// ones that cannot be enforced here at all.
//
// `lib/isolation/podman/argv.js` is entirely podman-flag-shaped and none of it transfers. There are
// no cgroups on macOS, so there is no memory cap, no CPU quota and no I/O weight; there is no tmpfs,
// so the workspace has no size limit; there are no namespaces, so `--userns` and `--cap-drop` have no
// analogue whatsoever. What is left is `ulimit`, a `TMPDIR` inside the job's scratch directory, and a
// wall-clock timer the launcher runs itself.
//
// The reason this file reports the gaps rather than quietly omitting them: `lib/attestation.js`
// already has the precedent. `forPublish` writes a deliberately different shape instead of a task
// record full of nulls, because "writing `null` into those would make an unsandboxed step look like a
// sandboxed one whose details went missing". A limits block listing only the four that worked reads
// as though all twelve were applied. A farm deciding whether to trust an artifact needs the
// difference, and this tier is exactly where the difference is largest.

// What a container tier enforces and this one does not. Each entry says what would be needed, so the
// list is a specification for closing a gap rather than a shrug.
const UNENFORCEABLE = {
  memoryBytes: 'no cgroups on macOS; RLIMIT_AS is per-process and does not bound a process tree',
  workspaceBytes: 'the workspace is a plain directory, not a tmpfs -- it would need a disk image',
  tmpBytes: 'same: TMPDIR is a directory inside the workspace and has no size of its own',
  shmBytes: 'no /dev/shm; SysV limits are global sysctls, not per job',
  headroomBytes: 'meaningless without a memory cap to hold headroom against',
  cpuQuota: 'no cgroup CPU controller; nice/taskpolicy are priority hints, not quotas',
  usernsSize: 'no user namespaces; a distinct uid needs a real account and root to switch to it',
  capabilities: 'no capability model to drop -- Seatbelt denies by policy instead'
}

const DEFAULTS = {
  // RLIMIT_NOFILE is the one clean port. The value matters: 4096 broke real builds, because
  // bare-pack traverses with unbounded concurrency and its reader swallows errno, so EMFILE
  // surfaced as `MODULE_NOT_FOUND` for a module that was right there.
  nofile: 65536,
  // Per-UID on macOS, not per-process-tree, so it collides with the developer's own session rather
  // than bounding the job. Kept because a runaway fork bomb still hits it, but it is a different
  // guarantee from --pids-limit and is recorded as such.
  nproc: 512,
  // No core dumps: a crashing build should not write a gigabyte into the workspace.
  core: 0,
  wallClockMs: 3600000
}

function resolve(spec = {}) {
  const o = { ...DEFAULTS, ...(spec || {}) }

  const applied = {
    nofile: o.nofile,
    nproc: o.nproc,
    core: o.core,
    wallClockMs: o.wallClockMs
  }

  // Anything the caller asked for that this tier cannot honour is reported back, not dropped. A
  // workflow that declared a memory cap deserves to know it was not applied.
  const requested = Object.keys(spec || {})
  const unenforceable = {}
  for (const [key, why] of Object.entries(UNENFORCEABLE)) {
    unenforceable[key] = requested.includes(key) ? `REQUESTED BUT NOT APPLIED -- ${why}` : why
  }

  return {
    applied,
    unenforceable,
    requestedButUnenforceable: requested.filter((k) => k in UNENFORCEABLE)
  }
}

// The `ulimit` prelude a step is wrapped in. Returned as a string rather than applied here because
// the limits have to be set in the child, and the agent runs each step through a shell anyway.
function prelude(applied) {
  return [
    `ulimit -n ${applied.nofile} 2>/dev/null || true`,
    `ulimit -u ${applied.nproc} 2>/dev/null || true`,
    `ulimit -c ${applied.core} 2>/dev/null || true`
  ].join('; ')
}

module.exports = { resolve, prelude, DEFAULTS, UNENFORCEABLE }
