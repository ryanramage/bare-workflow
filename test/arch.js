'use strict'

// Refusing an emulated build.
//
// Decision 2 says never emulation, and this is the control that enforces it. What makes it worth a
// test file of its own is that the failure it prevents is SILENT: a `podman machine` on Apple
// Silicon registers a `rosetta` binfmt handler for x86-64 ELF (plus qemu-user handlers for ~31 other
// architectures), so a foreign-arch image does not fail to start -- it runs, emulated, and gets
// attested exactly like a native build. Measured on this project's own Mac:
// `podman run --platform linux/amd64 ubuntu:24.04 uname -m` prints x86_64 on an arm64 host.
//
// `archOf` is injected throughout, so these assertions need no container runtime and hold on any
// machine -- including the CI box that has no podman at all.

const test = require('brittle')
const arch = require('../lib/isolation/arch.js')

const of = (map) => (image) => map[image] || null

test('a matching architecture is not foreign', (t) => {
  const foreign = arch.foreignImages(
    ['localhost/a:dev', 'localhost/b:dev'],
    'arm64',
    of({ 'localhost/a:dev': 'arm64', 'localhost/b:dev': 'arm64' })
  )
  t.alike(foreign, [], 'the normal case stays silent')
})

test('a foreign image is refused, and the error names both architectures', (t) => {
  const archOf = of({ 'docker.io/library/ubuntu:24.04': 'amd64' })
  const foreign = arch.foreignImages(['docker.io/library/ubuntu:24.04'], 'arm64', archOf)
  t.is(foreign.length, 1)
  t.is(foreign[0].arch, 'amd64')
  t.is(foreign[0].runtime, 'arm64')

  t.exception(
    () => arch.assertNative(['docker.io/library/ubuntu:24.04'], 'arm64', archOf),
    /IMAGE_ARCH_MISMATCH/
  )

  // The message has to say what to DO. "arch mismatch" sends someone hunting through podman docs;
  // naming both sides and the fix is the difference between a five-minute and a five-hour detour.
  const msg = arch.explain(foreign)
  t.ok(/amd64/.test(msg) && /arm64/.test(msg), 'both architectures appear')
  t.ok(/emulation/i.test(msg), 'and says WHY it is refused rather than just that it is')
  t.ok(/Rosetta|qemu/i.test(msg), 'naming the mechanism, so the message is recognisable')
  t.ok(/attestation/i.test(msg), 'and the real reason: an emulated build is attested as native')
})

test('the aliases podman and uname disagree on are normalized', (t) => {
  // podman reports Go names (amd64/arm64); uname and file(1) report x86_64/aarch64. Comparing the
  // two spellings as strings would refuse every image on a correctly configured machine.
  t.is(arch.normalize('x86_64'), 'amd64')
  t.is(arch.normalize('aarch64'), 'arm64')
  t.is(arch.normalize('ARM64'), 'arm64', 'case is not significant')
  t.is(arch.normalize('amd64'), 'amd64', 'and the canonical form is left alone')

  t.alike(
    arch.foreignImages(['i'], 'aarch64', of({ i: 'arm64' })),
    [],
    'aarch64 runtime and arm64 image are the SAME machine, not a mismatch'
  )
})

test('an unknown architecture is not treated as foreign', (t) => {
  // podman failing to answer is a different problem, reported elsewhere. Guessing here would turn an
  // unrelated podman outage into a confusing architecture error -- the diagnosis-trap shape this
  // project keeps running into.
  t.alike(
    arch.foreignImages(['i'], 'arm64', () => null),
    [],
    'no answer means no accusation'
  )
  t.alike(
    arch.foreignImages(['i'], null, () => 'amd64'),
    [],
    'and neither does an unknown runtime'
  )
})

test('every foreign image is reported, not just the first', (t) => {
  // A multi-toolchain workflow can have several images. Reporting one at a time means fixing them
  // one run at a time.
  const foreign = arch.foreignImages(
    ['a', 'b', 'c'],
    'arm64',
    of({ a: 'amd64', b: 'arm64', c: 'ppc64le' })
  )
  t.is(foreign.length, 2, 'both offenders')
  t.alike(
    foreign.map((f) => f.image),
    ['a', 'c']
  )
})
