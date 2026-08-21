'use strict'

// Runs the shared Sandbox lifecycle suite against every launcher this machine supports.
//
// Same assertions, three transports: a host subprocess (fast, no isolation, test-only), a hardened
// rootless container, and a krun microVM. Tiers that are unavailable are skipped with a reason
// rather than silently omitted -- a suite that quietly tests less than you think is worse than one
// that fails.

const test = require('brittle')
const { available } = require('./support/launchers.js')
const { lifecycleSuite } = require('./support/lifecycle.js')

const probe = available()

test('lifecycle: available tiers', (t) => {
  const names = probe.launchers.map((l) => l.name)
  t.comment('tiers under test: ' + names.join(', '))
  if (probe.reason) t.comment('some tiers skipped: ' + probe.reason)
  if (probe.krunError) t.comment('microvm skipped: ' + probe.krunError.trim().split('\n')[0])
  t.ok(names.includes('local'), 'the protocol-level launcher is always available')
  t.pass('probed')
})

for (const descriptor of probe.launchers) {
  lifecycleSuite(test, descriptor)
}
