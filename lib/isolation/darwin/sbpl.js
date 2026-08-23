'use strict'

// The Seatbelt profile, generated rather than hand-written.
//
// Same shape and the same reasons as lib/isolation/podman/seccomp.js: a pure function producing a
// reviewable document, a committed output, and a drift guard. The profile IS the boundary for this
// tier -- there is no namespace, no separate filesystem and no capability model behind it -- so it
// gets the same treatment as the seccomp profile: its sha256 goes into the attestation, and a change
// to it is a reviewable diff rather than a string edited in place.
//
// `(deny default)` and allow upward, never the reverse. Measured on Apple Silicon:
//
//   * `(deny default)` is tractable -- `/bin/echo` runs given process-exec, process-fork, file-read*.
//   * It fails CLOSED -- with nothing allowed, even execvp is refused ("Operation not permitted").
//   * `codesign` works under it, which is the whole premise of the tier.
//
// Deny-default also means host secrets need no explicit `deny` rules. That is not a tidiness win: an
// allowlist cannot be defeated by a path nobody thought to deny, and `~/.ssh` is exactly the sort of
// thing a denylist misses when someone adds `~/.aws` and stops thinking.

const WorkflowError = require('./../../errors.js')

const VERSION = 1

// Read-only system locations a build genuinely needs. Note what is absent: `/Users`, `/opt`, `/etc`
// as a subpath, and `/` as a subpath. The root is granted separately as a LITERAL, which is a
// different thing entirely -- see the comment where it is emitted.
const SYSTEM_READ = [
  '/usr/lib',
  '/usr/share',
  '/usr/bin',
  '/bin',
  '/sbin',
  '/usr/sbin',
  '/System',
  '/Library',
  '/private/var/db/dyld',
  '/private/var/db/timezone',
  '/dev/urandom',
  '/dev/random',
  '/dev/zero',
  '/dev/dtracehelper'
]

// Devices that must be WRITABLE, not merely readable. /dev/null is the one that matters: it is in
// essentially every shell script ever written, and granting it read-only produces
//   npm: line 2: /dev/null: Operation not permitted
// from inside a wrapper script, which looks like a broken npm rather than a sandbox rule.
const DEVICE_WRITE = ['/dev/null', '/dev/dtracehelper']

// Literals rather than subpaths: a build reads these to discover the machine, and a subpath grant
// under /private/etc would include far more than intended.
const SYSTEM_READ_FILES = [
  '/private/etc/localtime',
  '/private/etc/protocols',
  '/private/etc/services',
  // /bin/sh consults this to pick its personality and prints
  //   Error opening /private/var/select/sh: Operation not permitted
  // on every single invocation without it. The build still succeeds, which is worse than failing:
  // it is a permanent line of noise on top of every step's real output, and noise on a security
  // boundary is how people learn to ignore it.
  '/private/var/select/sh'
]

// macOS keeps the classic Unix names as symlinks into /private. A process resolving `/tmp/x` walks
// the LINK path as well as the resolved one, so granting the resolved ancestors is not enough -- the
// build failed on `lstat /var` with every /private ancestor already allowed. Metadata only: enough to
// readlink and traverse, not to read anything through them that is not separately granted.
const SYMLINK_ALIASES = ['/etc', '/tmp', '/var']

// Every directory between `/` and `path`, exclusive of both ends being special-cased by the caller.
//
// Granting `(subpath "/Users/ryan/.volta")` does NOT let a process `lstat("/Users")`, and resolving
// any path walks its ancestors -- so without these the build fails on the ancestor rather than on
// anything it was denied on purpose. Measured twice while writing this: first `lstat '/Users'`, then
// `lstat '/private'` once the first was granted.
//
// `file-read-metadata`, not `file-read*`: this permits stat on the directory entry, not listing it or
// reading anything inside. `/Users` becomes statable; `/Users/someone-else` stays invisible.
function ancestors(path) {
  const parts = path.split('/').filter(Boolean)
  const out = []
  let acc = ''
  for (let i = 0; i < parts.length - 1; i++) {
    acc += '/' + parts[i]
    out.push(acc)
  }
  return out
}

function quote(path) {
  if (typeof path !== 'string' || path.length === 0) {
    throw WorkflowError.INVALID_SPEC(`sandbox path must be a non-empty string, got ${path}`)
  }
  // SBPL is s-expressions: a quote or backslash in a path would end the string early and the rest
  // would be parsed as policy. There is no escaping story worth trusting here, so refuse instead --
  // this is a path we generate, not user input, and a path containing a quote is a bug either way.
  if (/["\\\n]/.test(path)) {
    throw WorkflowError.INVALID_SPEC(`sandbox path may not contain quotes or newlines: ${path}`)
  }
  return `"${path}"`
}

// Build the profile for one job.
//
//   workspace   the per-job scratch root; the ONLY writable location besides its own tmp
//   toolchain   read-only paths the build needs (the bare runtime, npm cache, Xcode)
//   allowNetwork  false by default, matching `--network none` on the container tiers
function generate(opts = {}) {
  const workspace = opts.workspace
  if (!workspace) throw WorkflowError.INVALID_SPEC('sandbox profile needs a workspace')
  const toolchain = opts.toolchain || []
  const lines = []

  lines.push(`;; bare-workflow seatbelt profile v${VERSION} -- GENERATED, do not edit`)
  lines.push(';;')
  lines.push(';; Regenerate with: bare scripts/build/sandbox.js')
  lines.push(';; The sha256 of the rendered profile is recorded in every attestation.')
  lines.push('(version 1)')
  lines.push('')
  lines.push(';; Deny everything, then grant. The inverse posture is not a sandbox.')
  lines.push('(deny default)')
  lines.push('')
  lines.push(';; A profile that is too tight fails in a genuinely unhelpful way -- SIGABRT with no')
  lines.push(';; message, because the loader dies before anything can report. Bisect the rules, or')
  lines.push(';; try: log stream --predicate \'sender == "Sandbox"\'')
  //
  // There is deliberately no `(deny default (with report))` here: sandbox-exec rejects the modifier
  // on a deny action outright ("report modifier does not apply to deny action") and then refuses to
  // load the profile at all -- which fails closed, but looks like a broken tier rather than a typo.
  lines.push('')

  lines.push(';; --- process ---------------------------------------------------------------')
  lines.push(';; A build forks compilers and shells; without these the profile cannot even exec.')
  lines.push('(allow process-fork)')
  lines.push('(allow process-exec)')
  lines.push('(allow signal (target same-sandbox))')
  lines.push('')
  lines.push(
    ';; Read-only kernel parameters. Cheap to grant and load-bearing in a way nothing about'
  )
  lines.push(';; the failure suggests: without it any Rust binary dies at startup with')
  lines.push(";;   panicked at 'failed to set up alternative stack guard page: Invalid argument'")
  lines.push(';; because the runtime queries page size and stack limits through sysctl and gets')
  lines.push(
    ';; EINVAL. Hit for real -- npm here is a Volta shim, which is written in Rust, so the'
  )
  lines.push(';; whole toolchain fell over with a message that never mentions the sandbox.')
  lines.push('(allow sysctl-read)')
  lines.push('')

  lines.push(';; --- read-only system ------------------------------------------------------')
  lines.push(
    ';; The root directory ENTRY, as a literal. Without it dyld cannot resolve anything and'
  )
  lines.push(';; every process dies with SIGABRT and no message at all -- not even /usr/bin/true')
  lines.push(
    ';; runs. Found by bisection, because the abort produces no diagnostic and the Sandbox'
  )
  lines.push(';; log yields nothing useful for it.')
  lines.push(';;')
  lines.push(
    ';; `literal`, emphatically not `subpath`. This grants the root entry itself and nothing'
  )
  lines.push(
    ';; beneath it; `(subpath "/")` would hand over the whole filesystem including the home'
  )
  lines.push(
    ';; directory this tier exists to protect, while looking like the same line of config.'
  )
  lines.push('(allow file-read* (literal "/"))')
  lines.push('')
  lines.push(';; Everything else is granted by explicit subpath. Note the absence of /Users.')
  for (const p of SYSTEM_READ) lines.push(`(allow file-read* (subpath ${quote(p)}))`)
  for (const p of DEVICE_WRITE) lines.push(`(allow file-read* file-write* (literal ${quote(p)}))`)
  for (const p of SYSTEM_READ_FILES) lines.push(`(allow file-read* (literal ${quote(p)}))`)
  lines.push('')

  lines.push(';; --- the toolchain ---------------------------------------------------------')
  if (toolchain.length === 0) {
    lines.push(';; (none declared)')
  } else {
    for (const p of [...toolchain].sort()) lines.push(`(allow file-read* (subpath ${quote(p)}))`)
  }
  lines.push('')

  lines.push(';; --- the workspace ---------------------------------------------------------')
  lines.push(';; The only writable location. Everything the build produces lands here, and the')
  lines.push(';; driver tars it out across the protocol exactly as the container tiers do.')
  lines.push(`(allow file* (subpath ${quote(workspace)}))`)
  lines.push('')

  lines.push(';; --- ancestor traversal -----------------------------------------------------')
  lines.push(
    ';; stat-only rights on the directories leading to everything granted above. Resolving'
  )
  lines.push(';; a path walks its ancestors, and a subpath grant does not imply them -- so without')
  lines.push(
    ';; these a build fails on `lstat /Users` or `lstat /private` rather than on anything it'
  )
  lines.push(';; was meant to be denied. `file-read-metadata` only: statable, not listable, not')
  lines.push(';; readable. /Users becomes statable; /Users/someone-else stays invisible.')
  const granted = [...SYSTEM_READ, ...SYSTEM_READ_FILES, ...DEVICE_WRITE, ...toolchain, workspace]
  const walked = [...new Set([...granted.flatMap(ancestors), ...SYMLINK_ALIASES])].sort()
  for (const p of walked) lines.push(`(allow file-read-metadata (literal ${quote(p)}))`)
  lines.push('')

  lines.push(';; --- what stays denied, stated for the reader -------------------------------')
  lines.push(
    ';; No network: matches --network none. Prefetch happens on the host before the sandbox'
  )
  lines.push(';; exists, so a build never needs egress.')
  lines.push(';; No mach-lookup beyond the defaults, no file-write outside the workspace, and')
  lines.push(';; therefore no reachable ~/.ssh, ~/.npmrc, ~/.aws or login keychain.')
  if (opts.allowNetwork) {
    lines.push('')
    lines.push(';; NETWORK EXPLICITLY ENABLED -- this is not the shipped posture.')
    lines.push('(allow network*)')
  }

  return lines.join('\n') + '\n'
}

// Stable, so a diff is reviewable and the drift guard means something.
function serialize(profile) {
  return typeof profile === 'string' ? profile : String(profile)
}

module.exports = { generate, serialize, VERSION, SYSTEM_READ, SYSTEM_READ_FILES, DEVICE_WRITE }
