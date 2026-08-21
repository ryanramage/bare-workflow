'use strict'

// Publishing: the one job kind that does NOT run in a sandbox.
//
// Everything else in this project assumes the workload is hostile and gives it nothing -- no
// network, no host filesystem, no host environment. Publishing cannot work that way. `pear stage`
// needs a Hyperswarm connection and the app's primary key, which is precisely the pair a sandbox
// exists to withhold. So rather than weakening the sandbox to fit, publishing moves OUTSIDE it and
// becomes a trusted step with a deliberately tiny surface:
//
//   * its only input is a NAMED ARTIFACT that a sandboxed job already produced and the store
//     already digest-bound, so what gets published is a reviewable tree rather than a live
//     directory some script was still writing to;
//   * it runs NO user code -- there is no `steps:`, no shell, nothing to inject into;
//   * the secret is named, never written: `key: hello-pear` resolves against runner-side config
//     that the workflow file cannot see and a build cannot read.
//
// That shape is the same one signing gets, and for the same reason. A compromised build can at
// worst produce a bad artifact; it can never reach the key that would let it publish one.

const DRIVERS = {
  'pear-ci': {
    describe: 'stateless `pear stage` via pear-ci: mirror a directory into a Hyperdrive',
    // What the driver needs from runner config, by name.
    secrets: ['primaryKey']
  }
}

function names() {
  return Object.keys(DRIVERS)
}

function resolve(name) {
  return DRIVERS[name] || null
}

module.exports = { DRIVERS, names, resolve }
