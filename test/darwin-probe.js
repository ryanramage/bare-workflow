'use strict'

// The Seatbelt probe: can this machine run a build natively AND sign the result?
//
// Worth its own file because the failure it prevents is a late, misattributed one. A machine with
// `sandbox-exec` but no Command Line Tools passes the obvious one-line check and then dies deep
// inside packaging with a missing `codesign`, which reads as a bug in the build rather than a missing
// dependency. Every check here exists because skipping it moves a failure later.

const test = require('brittle')
const os = require('bare-os')
const darwin = require('../lib/isolation/darwin/probe.js')

test('off macOS it is a fact about the platform, not a missing dependency', (t) => {
  for (const platform of ['linux', 'win32']) {
    const r = darwin.probe({ platform, profile: '/anything' })
    t.absent(r.available, `${platform}: never available`)
    t.ok(/macOS-only/.test(r.reason), `${platform}: says why -- ${r.reason}`)
    // Deliberately no remediation. There is nothing to install; it is the wrong machine. Offering a
    // fix here would be the `pacman -S libkrun on a Mac` mistake pointing the other way, and decision
    // 4 rests entirely on remediation being actionable.
    t.absent(r.remediation, `${platform}: offers no unfollowable fix`)
  }
})

test('a missing profile is refused, with the command that makes one', (t) => {
  if (os.platform() !== 'darwin') {
    t.comment('the profile check only runs on macOS, where the tools exist')
    return t.pass('skipped')
  }
  const r = darwin.probe({ profile: '/definitely/not/here/build-v1.sb' })
  t.absent(r.available, 'no profile, no tier')
  t.ok(/profile missing/.test(r.reason), 'names the problem: ' + r.reason)
  t.ok(/scripts\/build\/sandbox\.js/.test(r.remediation), 'and the command: ' + r.remediation)
})

test('the probe requires every tool, not just the first', (t) => {
  // `sandbox-exec` alone is not enough to build anything, and `codesign` existing is not the same as
  // the toolchain working -- /usr/bin/codesign is a stub that is present with no CLT installed and
  // only fails when invoked. Asserted as a list so adding a tool cannot silently skip its check.
  t.ok(darwin.TOOLS.length >= 2, 'more than one tool is checked')
  const names = darwin.TOOLS.map((x) => x.bin)
  t.ok(names.includes('sandbox-exec'), 'confinement')
  t.ok(names.includes('codesign'), 'signing')
  for (const tool of darwin.TOOLS) {
    t.ok(tool.why && tool.why.length > 0, `${tool.bin} says what it is for`)
    t.ok(tool.fix && tool.fix.length > 0, `${tool.bin} says how to get it`)
  }
})

test('on this Mac the toolchain half genuinely passes', (t) => {
  if (os.platform() !== 'darwin') return t.pass('not a Mac')
  // Passing a profile that exists isolates the TOOLCHAIN checks from the profile gate: if this fails,
  // the machine is missing sandbox-exec, codesign or the CLT, which is a real finding rather than
  // "the tier is not built yet".
  const r = darwin.probe({ profile: __filename })
  t.ok(r.available, 'sandbox-exec, codesign and the CLT are all present: ' + (r.reason || 'ok'))
  t.ok(r.developerDir && r.developerDir.length > 0, 'and xcode-select names a developer dir')
})
