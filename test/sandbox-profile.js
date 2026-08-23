'use strict'

// The Seatbelt profile generator.
//
// This profile IS the boundary for the seatbelt tier -- no namespace, no separate filesystem, no
// capability model behind it -- so it gets the same treatment as the seccomp profile: a pure
// generator, a reviewable rendering, and a drift guard.
//
// Most of what is asserted here was learned by a build failing. A too-tight SBPL profile fails in an
// exceptionally unhelpful way: SIGABRT with no message, because the loader dies before anything can
// report. Each rule below has a failure attached to it, and the comments say which.

const test = require('brittle')
const fs = require('bare-fs')
const os = require('bare-os')
const path = require('bare-path')
const { spawnSync } = require('bare-subprocess')

const sbpl = require('../lib/isolation/darwin/sbpl.js')

const spec = { workspace: '/private/tmp/bw-profile-test', toolchain: ['/opt/toolchain'] }

// The rules only. The profile documents its own sharp edges in `;;` comments, so a naive substring
// search finds the dangerous form quoted in the warning against it.
const rules = (profile) =>
  profile
    .split('\n')
    .filter((l) => !l.trimStart().startsWith(';;'))
    .join('\n')

test('the posture is deny-default, which is the whole point', (t) => {
  const p = sbpl.generate(spec)
  t.ok(/^\(deny default\)$/m.test(p), 'denies by default')
  t.absent(/\(allow default\)/.test(p), 'and never the inverse -- that is not a sandbox')

  // Deny-default is why there are no explicit `deny` rules for host secrets: an allowlist cannot be
  // defeated by a path nobody thought to add to a denylist.
  t.absent(/\/Users/.test(rules(p)), 'no home directory appears in any rule')
})

test('the root is granted as a LITERAL, never a subpath', (t) => {
  // The single most dangerous one-character difference in the file. `(literal "/")` grants the root
  // directory entry, which dyld needs -- without it every process dies with SIGABRT and no output,
  // not even /usr/bin/true. `(subpath "/")` would grant the entire filesystem while looking almost
  // identical in a diff.
  // Comment lines stripped first: the profile EXPLAINS this distinction in prose, and the prose
  // necessarily contains the dangerous form it is warning about.
  const p = rules(sbpl.generate(spec))
  t.ok(p.includes('(allow file-read* (literal "/"))'), 'the root entry is readable')
  t.absent(p.includes('(subpath "/")'), 'but the filesystem is NOT')
})

test('ancestors are granted stat-only, so traversal works without reading', (t) => {
  // Granting `(subpath "/opt/toolchain")` does not permit `lstat("/opt")`, and resolving a path walks
  // its ancestors -- the build failed on `lstat /Users`, then `lstat /private`, then `lstat /var`.
  const p = sbpl.generate({ workspace: '/private/tmp/ws', toolchain: ['/opt/toolchain'] })
  t.ok(p.includes('(allow file-read-metadata (literal "/opt"))'), 'the toolchain ancestor')
  t.ok(p.includes('(allow file-read-metadata (literal "/private"))'), 'the workspace ancestor')
  t.absent(p.includes('(allow file-read* (subpath "/opt"))'), 'metadata only, never a read grant')

  // macOS keeps /etc /tmp /var as symlinks into /private, and a process walks the LINK path too.
  for (const alias of ['/etc', '/tmp', '/var']) {
    t.ok(
      p.includes(`(allow file-read-metadata (literal "${alias}"))`),
      `${alias} is traversable -- it is a symlink into /private`
    )
  }
})

test('sysctl-read is granted, and the reason is not guessable', (t) => {
  // Without it EVERY Rust binary dies at startup with "failed to set up alternative stack guard
  // page: Invalid argument". Hit for real: npm on this machine is a Volta shim, which is Rust, so the
  // whole toolchain fell over with a message that never mentions the sandbox.
  t.ok(sbpl.generate(spec).includes('(allow sysctl-read)'))
})

test('the workspace is the only writable location', (t) => {
  const p = sbpl.generate(spec)
  const writes = p.split('\n').filter((l) => /^\(allow file\*/.test(l) || /file-write/.test(l))
  const grants = writes.filter((l) => /^\(allow file\*/.test(l))
  t.is(grants.length, 1, 'exactly one write grant: ' + grants.join(' | '))
  t.ok(grants[0].includes(spec.workspace), 'and it is the workspace')
})

test('network is denied unless explicitly asked for', (t) => {
  t.absent(/\(allow network/.test(sbpl.generate(spec)), 'matches --network none by default')
  t.ok(
    /\(allow network\*\)/.test(sbpl.generate({ ...spec, allowNetwork: true })),
    'and the escape hatch is explicit and greppable, for the negative control to use'
  )
})

test('a path that could break out of the s-expression is refused', (t) => {
  // SBPL is s-expressions: an unescaped quote in a path ends the string and the remainder is parsed
  // as policy. Rather than invent an escaping story, refuse -- these are paths we generate.
  t.exception(() => sbpl.generate({ workspace: '/tmp/a"b' }), /INVALID_SPEC/)
  t.exception(() => sbpl.generate({ workspace: '/tmp/a\nb' }), /INVALID_SPEC/)
  t.exception(() => sbpl.generate({ workspace: '' }), /INVALID_SPEC/)
})

test('the committed rendering matches the generator (drift guard)', (t) => {
  // Same purpose as the seccomp drift guard: catch "someone changed the generator and did not
  // regenerate". Note the committed file is the CANONICAL rendering against fixed inputs -- it is not
  // the profile that runs, because a real one names the job's workspace. The running profile's
  // sha256 is what the attestation records.
  const file = path.join(__dirname, '..', 'etc/sandbox/build-v1.sb')
  let committed
  try {
    committed = fs.readFileSync(file, 'utf8')
  } catch {
    t.comment('no committed rendering; run: bare scripts/build/sandbox.js')
    return t.pass('skipped')
  }
  const expected = sbpl.serialize(
    sbpl.generate({ workspace: '/w', toolchain: ['/CANONICAL/toolchain'] })
  )
  t.is(committed, expected, 'regenerate and commit: bare scripts/build/sandbox.js')
})

test('the generated profile is one sandbox-exec actually accepts', (t) => {
  // A profile that does not LOAD is the failure mode this whole file exists around, and it is not
  // detectable by reading: sandbox-exec rejected `(deny default (with report))` outright, and a
  // missing root literal produced a silent SIGABRT. So load a real one and run something under it.
  if (os.platform() !== 'darwin') {
    t.comment('sandbox-exec is macOS-only')
    return t.pass('skipped')
  }

  const dir = '/private/tmp/bw-sbpl-' + Date.now()
  fs.mkdirSync(dir, { recursive: true })
  const profile = dir + '/p.sb'
  fs.writeFileSync(profile, sbpl.generate({ workspace: dir, toolchain: [] }))
  try {
    const ran = spawnSync('/usr/bin/sandbox-exec', ['-f', profile, '/bin/echo', 'loaded'], {
      env: {}
    })
    const out = ran.stdout ? ran.stdout.toString() : ''
    t.is(ran.status, 0, 'the profile loads and a process runs under it')
    t.ok(out.includes('loaded'), 'and its output survives: ' + JSON.stringify(out.trim()))

    // The other half: it must still DENY. A profile permissive enough to run anything is not a
    // boundary, and this is the assertion that would catch someone "fixing" a build failure by
    // widening the profile until the problem went away.
    const home = require('bare-env').HOME
    if (home) {
      const denied = spawnSync('/usr/bin/sandbox-exec', ['-f', profile, '/bin/ls', home], {
        env: {}
      })
      t.not(denied.status, 0, 'and reading the host home directory is refused')
    }
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true })
    } catch {}
  }
})
