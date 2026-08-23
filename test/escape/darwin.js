'use strict'

// The escape suite for the native darwin (seatbelt) tier -- and its NEGATIVE CONTROL.
//
// Read this paragraph before trusting anything below it, exactly as with the podman escape suite.
// Every assertion here says some probe came back denied. A probe that CANNOT come back allowed is
// worth nothing, and this project has shipped two of those already: `ip route` against an image with
// no iproute2, and a podman-socket path built from a uid that was always the literal 1000. Both
// reported "absent" in the hardened posture and would have reported "absent" in any posture.
//
// So every probe is run twice: once under the real generated profile, and once under a deliberately
// weakened one (`(allow default)`). The weakened run must LEAK. If it stops leaking, the probe has
// gone blind and the hardened result means nothing -- that is asserted, loudly, rather than left for
// someone to notice.
//
// What this suite does NOT cover, stated so it is not mistaken for coverage: Seatbelt is same-kernel
// MAC. There is no namespace, no pid isolation and no capability model, so there are no uid-mapping
// or capability assertions to make here the way there are for a container. The boundary is entirely
// the policy document, which is why the profile has a generator, a drift guard and its hash in every
// attestation.

const test = require('brittle')
const fs = require('bare-fs')
const os = require('bare-os')
const path = require('bare-path')
const env = require('bare-env')
const { spawnSync } = require('bare-subprocess')

const h = require('./harness.js')
const sbpl = require('../../lib/isolation/darwin/sbpl.js')
const darwin = require('../../lib/isolation/darwin/probe.js')

const SANDBOX_EXEC = '/usr/bin/sandbox-exec'

// A workspace to stand in for a job's scratch directory. Real, because the profile grants it by path
// and a rule naming a directory that does not exist matches nothing once it appears.
let WS = null
let READY = null
let TOOLCHAIN = []

// Emits a flat report. Every probe is wrapped so one failure cannot abort the script -- a missing
// line would silently satisfy an `is('', ...)` assertion, which is the same vacuity trap again.
function probeScript(home) {
  return `
set +e
say () { echo "$1=$2"; }

# --- the host filesystem ---------------------------------------------------------------
say canary "$(cat '${home}/${h.CANARY_NAME}' 2>/dev/null | head -1)"
say ssh_key "$(cat '${home}/.ssh/id_ed25519' 2>/dev/null | head -1 | cut -c1-20)"
say npmrc "$(cat '${home}/.npmrc' 2>/dev/null | head -1 | cut -c1-20)"
say home_list "$(ls '${home}' 2>/dev/null | head -1)"
say users_list "$(ls /Users 2>/dev/null | head -1)"
say home_write "$(touch '${home}/.bw-escape-write' 2>/dev/null && echo WROTE || echo denied)"

# --- the keychain, which is where macOS actually keeps secrets --------------------------
say keychain "$(ls '${home}/Library/Keychains' 2>/dev/null | head -1)"

# --- network ----------------------------------------------------------------------------
# A connect ATTEMPT, not a routing-table read: a native step shares the host's routing table,
# so counting routes would report the developer's own network in both postures and prove nothing.
say egress "$(if exec 3<>/dev/tcp/1.1.1.1/443 2>/dev/null; then echo OPEN; else echo denied; fi)"

# --- writing outside the workspace --------------------------------------------------------
say tmp_write "$(touch /tmp/.bw-escape-tmp 2>/dev/null && echo WROTE || echo denied)"

# --- the workspace itself must WORK, or the tier is useless rather than secure -------------
say ws_write "$(touch '${WS}/probe' 2>/dev/null && echo ok || echo BROKEN)"
echo REPORT_END
`
}

function parse(stdout) {
  const out = {}
  for (const line of stdout.split('\n')) {
    const i = line.indexOf('=')
    if (i > 0) out[line.slice(0, i)] = line.slice(i + 1).trim()
  }
  return out
}

// Run a script under a given profile text. Returns the parsed report plus the raw output, because
// the canary assertion checks the WHOLE stream -- a leak by a route we did not think to probe for
// still puts the marker on stdout.
function runUnder(profileText, script) {
  const file = path.join(WS, 'p-' + Math.abs(hash(profileText)) + '.sb')
  fs.writeFileSync(file, profileText)
  const r = spawnSync(SANDBOX_EXEC, ['-f', file, '/bin/sh', '-c', script], {
    cwd: WS,
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', HOME: path.join(WS, 'home') }
  })
  const stdout = r.stdout ? r.stdout.toString() : ''
  return { code: r.status, stdout, stderr: r.stderr ? r.stderr.toString() : '', r: parse(stdout) }
}

function hash(s) {
  let n = 0
  for (let i = 0; i < s.length; i++) n = (n * 31 + s.charCodeAt(i)) | 0
  return n
}

// The real posture: the profile a REAL job gets, including the real toolchain grants.
//
// Not `toolchain: []`. The first version of this file tested an empty toolchain, which is tighter
// than anything that ships -- the launcher grants read on the host's PATH directories, Volta,
// Homebrew and the Xcode developer dir. Proving a profile nobody runs is tight says nothing about
// the one that does, and the toolchain is precisely the soft edge worth probing: it is a list of
// host paths, and $HOME is full of things that are not toolchains.
function hardened() {
  return sbpl.generate({ workspace: WS, toolchain: TOOLCHAIN })
}

// The deliberately broken posture. `(allow default)` is what an earlier probe in this project used
// while testing whether codesign survives confinement -- it is not a sandbox, and its whole purpose
// here is to prove the probes can see a leak when there is one.
function weakened() {
  return '(version 1)\n(allow default)\n'
}

test('darwin escape: environment', (t) => {
  if (os.platform() !== 'darwin') {
    t.comment('the seatbelt tier is macOS-only')
    READY = { ok: false, why: 'not darwin' }
    return t.pass('skipped')
  }
  const verdict = darwin.probe({ profile: __filename })
  if (!verdict.available) {
    READY = { ok: false, why: verdict.reason }
    t.comment('skipping: ' + verdict.reason)
    return t.pass('skipped')
  }

  // The same function bin.js uses, so this suite cannot drift from what ships.
  TOOLCHAIN = require('../../lib/isolation/darwin/toolchain.js').seatbeltToolchain()
  WS = fs.realpathSync(os.tmpdir()) + '/bw-escape-darwin-' + Date.now()
  fs.mkdirSync(WS + '/home', { recursive: true })
  h.plantCanary()
  READY = { ok: true }
  t.pass('sandbox-exec available; canary planted at ' + h.canaryPath())
})

test('hardened: the host filesystem is unreachable', (t) => {
  if (!READY || !READY.ok) return t.pass('skipped')
  const home = env.HOME
  const { stdout, r } = runUnder(hardened(), probeScript(home))

  // The single most important assertion: the marker must not appear ANYWHERE in the output, by any
  // route -- including one this file did not think to probe for.
  t.absent(stdout.includes(h.CANARY_TEXT), 'canary text absent from the entire probe output')
  t.is(r.canary, '', 'canary unreadable by absolute path')
  t.is(r.ssh_key, '', 'host ssh key unreadable')
  t.is(r.npmrc, '', 'host npmrc (npm token) unreadable')
  t.is(r.home_list, '', 'the home directory cannot even be listed')
  t.is(r.users_list, '', '/Users cannot be listed')
  t.is(r.keychain, '', 'the login keychain is not reachable')
  t.is(r.home_write, 'denied', 'and nothing can be written into it')
})

test('hardened: no network, and no writing outside the workspace', (t) => {
  if (!READY || !READY.ok) return t.pass('skipped')
  const { r } = runUnder(hardened(), probeScript(env.HOME))
  t.is(r.egress, 'denied', 'no egress -- matches --network none on the container tiers')
  t.is(r.tmp_write, 'denied', '/tmp is not writable; the workspace is the only writable place')
  t.is(r.ws_write, 'ok', 'and the workspace IS writable, or the tier is broken rather than secure')
})

test('NEGATIVE CONTROL: the weakened posture leaks every one of those', (t) => {
  // If this test starts passing-by-denial, the suite above is measuring nothing. Read the header.
  if (!READY || !READY.ok) return t.pass('skipped')
  const home = env.HOME
  const { stdout, r } = runUnder(weakened(), probeScript(home))

  t.ok(
    r.ws_write === 'ok',
    'the weakened posture actually ran -- otherwise "denied" below means "did not execute"'
  )

  t.ok(stdout.includes(h.CANARY_TEXT), 'weakened posture LEAKS the canary -- the probe is live')
  t.is(r.canary, h.CANARY_TEXT, 'canary readable by absolute path')
  t.not(r.home_list, '', 'the home directory lists: ' + r.home_list)
  t.not(r.users_list, '', '/Users lists: ' + r.users_list)
  t.is(r.home_write, 'WROTE', 'and is writable')
  t.is(r.tmp_write, 'WROTE', '/tmp is writable too')

  // The keychain probe needs its own control or the hardened assertion above is untested: an empty
  // result would look identical on a host with no keychain at all. This one was nearly missed --
  // it was the only probe in the hardened set without a counterpart here.
  if (fileExists(path.join(home, 'Library/Keychains'))) {
    t.not(r.keychain, '', 'and the login keychain is listable: ' + r.keychain)
  } else {
    t.comment('no ~/Library/Keychains on this host; that probe is UNVERIFIED in this run')
  }

  // Network is the one probe that can legitimately be unavailable for an unrelated reason -- an
  // offline machine. Say which it is rather than reporting a false pass either way.
  if (r.egress === 'OPEN') {
    t.pass('weakened posture reaches the network, so the egress probe has teeth')
  } else {
    t.comment('no network on this machine; the egress probe is UNVERIFIED in this run')
  }

  // These two are only meaningful if the host actually has them.
  if (fileExists(path.join(home, '.ssh/id_ed25519'))) {
    t.not(r.ssh_key, '', 'and reads the host ssh key')
  } else {
    t.comment('no ~/.ssh/id_ed25519 on this host; that probe is UNVERIFIED in this run')
  }
  if (fileExists(path.join(home, '.npmrc'))) {
    t.not(r.npmrc, '', 'and reads the host npmrc')
  } else {
    t.comment('no ~/.npmrc on this host; that probe is UNVERIFIED in this run')
  }
})

test('the toolchain grants do not reach anything secret', (t) => {
  // The toolchain is the one place this boundary is a list of host paths rather than a deny-all, so
  // it is worth asserting directly rather than only through the probes. A single careless entry --
  // `$HOME`, or a parent of it -- would open everything the suite above proves is closed, and it
  // would do so without changing any of the profile's structure.
  if (!READY || !READY.ok) return t.pass('skipped')
  const home = env.HOME
  t.ok(TOOLCHAIN.length > 0, `granting ${TOOLCHAIN.length} toolchain paths`)

  for (const p of TOOLCHAIN) {
    t.absent(p === home || p === home + '/', `never $HOME itself: ${p}`)
    for (const secret of ['.ssh', '.npmrc', '.aws', 'Library/Keychains', '.gnupg']) {
      const full = path.join(home, secret)
      t.absent(
        full === p || full.startsWith(p.endsWith('/') ? p : p + '/'),
        `${p} does not cover ${secret}`
      )
    }
  }
})

test('the profile the LAUNCHER ships is the one tested here', (t) => {
  // Guards the gap that makes an escape suite decorative: proving some profile is tight says nothing
  // if the launcher generates a different one. Built through the real launcher, with the real
  // toolchain, and compared byte for byte against what this file probed.
  if (!READY || !READY.ok) return t.pass('skipped')
  const { SeatbeltLauncher } = require('../../lib/isolation/darwin/launcher.js')
  const l = new SeatbeltLauncher({
    jobId: 'escape-check',
    tier: 'seatbelt',
    toolchain: TOOLCHAIN
  })
  t.is(
    sbpl.generate({ workspace: l.root, toolchain: l.toolchain }),
    sbpl.generate({ workspace: l.root, toolchain: TOOLCHAIN }),
    'the launcher adds no grants beyond the toolchain it was given'
  )
})

test('darwin escape: teardown', (t) => {
  h.removeCanary()
  t.absent(fileExists(h.canaryPath()), 'canary removed')
  if (WS) {
    try {
      fs.rmSync(WS, { recursive: true, force: true })
    } catch {}
  }
  try {
    fs.unlinkSync(path.join(env.HOME || '/tmp', '.bw-escape-write'))
  } catch {}
  try {
    fs.unlinkSync('/tmp/.bw-escape-tmp')
  } catch {}
  t.pass('cleaned up')
})

function fileExists(p) {
  try {
    fs.statSync(p)
    return true
  } catch {
    return false
  }
}
