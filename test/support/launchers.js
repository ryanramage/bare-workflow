'use strict'

// Enumerates the launchers available on this machine, so one lifecycle suite can run across all
// of them.
//
// This is the join between the two halves of the test suite. The escape suite proves the isolation
// posture holds; the lifecycle suite proves the protocol works. Running the lifecycle suite through
// the REAL container and microVM launchers means we are no longer trusting that the two compose --
// we are testing it.

const { spawnSync } = require('bare-subprocess')
const path = require('bare-path')
const os = require('bare-os')
const { hostEnv, which } = require('../../lib/host-env.js')

const { LocalLauncher } = require('./local-launcher.js')
const { create: podmanLauncher } = require('../../lib/isolation/podman/launcher.js')

const IMAGE_REF = 'localhost/bare-workflow-base'
const IMAGE_TAG = 'dev'
const PROFILE = path.resolve('etc/seccomp/build-v1.json')

// Synchronous on purpose: CJS has no top-level await, and making available() async would force
// every consumer to register its tests from inside a callback. The probe runs once per process.
//
// The `timeoutMs` argument this used to take was passed to spawnSync as `timeout`, an option
// bare-subprocess does not implement -- inert since the day it was written. It is gone rather than
// left looking like a guard. The `which` check is load bearing: spawning an absent binary throws
// ENOENT and then makes bare exit 144 at teardown even when the throw is caught.
function sh(file, args) {
  if (which(file) === null) {
    return { code: -1, stdout: '', stderr: `${file} not found on PATH`, missing: true }
  }
  try {
    const r = spawnSync(file, args, { env: hostEnv() })
    return {
      code: r.status === null ? -1 : r.status,
      stdout: r.stdout ? r.stdout.toString() : '',
      stderr: r.stderr ? r.stderr.toString() : '',
      missing: false
    }
  } catch (err) {
    return { code: -1, stdout: '', stderr: String(err), missing: false }
  }
}

let cached = null

// Probe once per process: podman calls are slow enough that repeating them per test file is
// noticeable, and the answer cannot change mid-run.
function available() {
  if (cached) return cached

  const out = [
    {
      // Always available. NO ISOLATION -- it exists to exercise the protocol quickly, and it lives
      // under test/ so the product cannot select it. See local-launcher.js.
      name: 'local',
      isolated: false,
      make: () => new LocalLauncher(),
      // This one runs on the host, so unlike every isolated tier its platform is the host's.
      expectPlatform: os.platform(),
      // The host has no /w, so steps need a cwd that exists here.
      cwd: os.tmpdir ? os.tmpdir() : '/tmp'
    }
  ]

  // `info` asks the server, which is the thing that has to work. `version` succeeds against a
  // client whose machine is stopped on Linux and fails opaquely everywhere else; on macOS a stopped
  // machine is the normal state of a correct install, so "podman unavailable" was the single most
  // misleading string in the suite.
  const v = sh('podman', ['info', '--format', '{{.Version.Version}}'])
  if (v.code !== 0) {
    cached = {
      launchers: out,
      reason: v.missing
        ? 'podman not found on PATH'
        : 'podman did not answer: ' + (v.stderr.trim().split('\n')[0] || `exit ${v.code}`)
    }
    return cached
  }

  const d = sh('podman', [
    'image',
    'inspect',
    `${IMAGE_REF}:${IMAGE_TAG}`,
    '--format',
    '{{.Digest}}'
  ])
  if (d.code !== 0) {
    cached = {
      launchers: out,
      reason: `${IMAGE_REF}:${IMAGE_TAG} not built -- run: bare scripts/build/agent.js`
    }
    return cached
  }
  const digest = d.stdout.trim()

  const spec = (tier, jobId) => ({
    jobId,
    tier,
    image: { ref: IMAGE_REF, digest },
    seccompProfile: PROFILE,
    // The systemd scope is orthogonal to the protocol and covered by test/argv-runs.js; leaving it
    // off keeps a scope failure from masquerading as a protocol failure.
    scope: false
  })

  let n = 0
  out.push({
    name: 'container',
    isolated: true,
    expectUid: '1000',
    make: () => podmanLauncher(spec('container', `bwlife-c${n++}`))
  })

  // Does krun actually work right now? Cheaper to ask once than to have every microvm test fail
  // identically.
  const k = sh('podman', [
    'run',
    '--rm',
    '--annotation',
    'run.oci.handler=krun',
    '--device',
    '/dev/kvm',
    '--network',
    'none',
    '--log-driver',
    'none',
    '--entrypoint',
    '/bin/sh',
    `${IMAGE_REF}@${digest}`,
    '-c',
    'true'
  ])

  if (k.code === 0) {
    out.push({
      name: 'microvm',
      isolated: true,
      // krun does not apply --user to the guest: the workload is uid 0 inside its own kernel. That
      // is correct -- the VM is the boundary, not the capability set -- so uid expectations differ
      // per tier and the suite must not assume otherwise.
      expectUid: '0',
      make: () => podmanLauncher(spec('microvm', `bwlife-m${n++}`))
    })
  }

  cached = {
    launchers: out,
    digest,
    microvm: k.code === 0,
    krunError: k.code === 0 ? null : k.stderr
  }
  return cached
}

module.exports = { available, IMAGE_REF, IMAGE_TAG, PROFILE }
