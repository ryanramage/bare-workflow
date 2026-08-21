'use strict'

// Target vocabulary tests.
//
// `satisfies()` is the interesting one. Today it is called with the LOCAL capability record; in the
// farm the identical call is made against an announced peer's record and becomes the routing
// decision. Testing it properly now is what keeps that from being a redesign later.

const test = require('brittle')
const targets = require('../lib/targets.js')

test("the vocabulary is pear-build's, plus host", (t) => {
  // These strings end up as `pear build --<target>-app` flags, so they are not ours to invent.
  for (const name of [
    'linux-x64',
    'darwin-arm64',
    'win32-x64',
    'ios-arm64-simulator',
    'android-arm64'
  ]) {
    t.ok(targets.TARGETS.includes(name), name + ' is known')
  }
  t.absent(targets.TARGETS.includes('host'), 'host is a pseudo-target, not a build target')
  t.ok(targets.ALL.includes('host'))
})

test('parse splits platform from arch on the FIRST dash', (t) => {
  t.alike(targets.parse('darwin-arm64'), {
    name: 'darwin-arm64',
    platform: 'darwin',
    arch: 'arm64',
    host: false
  })
  // The reason it must be the first dash and not the last:
  t.alike(targets.parse('ios-arm64-simulator'), {
    name: 'ios-arm64-simulator',
    platform: 'ios',
    arch: 'arm64-simulator',
    host: false
  })
  t.alike(targets.parse('host'), { name: 'host', platform: null, arch: null, host: true })
})

test('unknown targets throw rather than being guessed at', (t) => {
  t.exception(() => targets.parse('darwin-arm46'), /UNKNOWN_TARGET/)
  t.exception(() => targets.parse('freebsd-x64'), /UNKNOWN_TARGET/)
  t.exception(() => targets.parse(''), /UNKNOWN_TARGET/)
  t.exception(() => targets.parse(null), /UNKNOWN_TARGET/)
})

test('describe reports every target this host can produce a USABLE binary for', (t) => {
  // This replaced a per-platform model ("no darwin from linux"), which was accidentally right for
  // darwin-arm64 and needlessly wrong for everything else. bare-build never compiles -- it injects
  // the bundle into a prebuilt runtime with bare-lief -- so cross-linking always works. The only
  // real constraint is a signature the host cannot issue. Measured, not assumed.
  const linux = targets.describe({ platform: 'linux', arch: 'x64' })
  t.ok(linux.targets.includes('win32-x64'), 'PE injection needs no Windows')
  t.ok(linux.targets.includes('win32-arm64'))
  t.ok(
    linux.targets.includes('darwin-x64'),
    'the x64 mach-o runtime has no signature to invalidate'
  )
  t.ok(linux.targets.includes('linux-arm64'))
  t.absent(
    linux.targets.includes('darwin-arm64'),
    'an arm64 mach-o must be signed, and only a mac can'
  )

  const mac = targets.describe({ platform: 'darwin', arch: 'arm64' })
  t.ok(mac.targets.includes('darwin-arm64'), 'which is exactly what a mac peer is for')
  t.ok(mac.targets.includes('ios-arm64'), 'ios always needs a signature too')
  t.ok(mac.targets.includes('linux-x64'), 'and a mac can cross-link linux just as well')
})

test('the record separates "cannot build" from "cannot sign"', (t) => {
  // The distinction is what routing to a mac peer actually solves, so a farm needs it explicitly.
  const linux = targets.describe({ platform: 'linux', arch: 'x64' })
  t.ok(linux.unsignable.includes('darwin-arm64'))
  t.ok(linux.unsignable.includes('ios-arm64'))
  t.absent(linux.unsignable.includes('win32-x64'), 'unsigned windows binaries still run')
  t.alike(
    targets.describe({ platform: 'darwin', arch: 'arm64' }).unsignable,
    [],
    'a mac has no gap'
  )
})

test('the capability record is shaped like a future announcement', (t) => {
  const caps = targets.describe({ platform: 'linux', arch: 'x64', tiers: ['microvm'] })
  t.is(caps.version, 1, 'versioned, because peers will exchange this')
  t.ok(Array.isArray(caps.targets))
  t.alike(caps.tiers, ['microvm'], 'the tier is part of the record, so a peer can be chosen by it')
  t.ok(caps.cpus >= 1)
})

test('satisfies: host is unconstrained, everything else must be declared', (t) => {
  const caps = targets.describe({ platform: 'linux', arch: 'x64' })
  t.ok(targets.satisfies(caps, 'host'), 'every peer can run unconstrained work')
  t.ok(targets.satisfies(caps, 'linux-x64'))
  t.absent(targets.satisfies(caps, 'darwin-arm64'))

  // Accepts either a string or a parsed target -- the farm will have the parsed form to hand.
  t.ok(targets.satisfies(caps, targets.parse('linux-arm64')))
  t.absent(targets.satisfies(null, 'linux-x64'), 'no capabilities satisfies nothing')
})

test('unsatisfied names exactly what cannot be built here', (t) => {
  const caps = targets.describe({ platform: 'linux', arch: 'x64' })
  t.alike(
    targets.unsatisfied(caps, ['host', 'linux-x64', 'darwin-arm64', 'win32-x64']),
    ['darwin-arm64'],
    'only the target that genuinely cannot be produced -- win32 cross-builds fine'
  )
  t.alike(targets.unsatisfied(caps, ['host']), [])
  t.alike(targets.unsatisfied(caps, []), [])
})

test('a mac peer satisfies what a linux peer cannot -- the farm premise', (t) => {
  // The reason the farm exists at all: `pear build` needs real machines per OS, so these two
  // records between them cover a workflow neither can complete alone.
  const linux = targets.describe({ platform: 'linux', arch: 'x64' })
  const mac = targets.describe({ platform: 'darwin', arch: 'arm64' })
  const wanted = ['linux-x64', 'darwin-arm64']

  // The premise is narrower than it used to look, and better for being true: a Linux peer covers
  // five of six desktop targets on its own, and needs a mac for exactly one -- darwin-arm64, because
  // only a mac can issue the signature Apple Silicon demands.
  t.alike(targets.unsatisfied(linux, wanted), ['darwin-arm64'], 'the one real gap')
  t.alike(targets.unsatisfied(mac, wanted), [], 'a mac happens to cover both')
  const both = wanted.filter((w) => targets.satisfies(linux, w) || targets.satisfies(mac, w))
  t.alike(both, wanted, 'together they cover it')
})
