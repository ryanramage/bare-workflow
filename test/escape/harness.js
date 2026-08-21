'use strict'

// Shared harness for the escape suite.
//
// Two postures run the SAME probes:
//
//   hardened  -- argv straight from lib/isolation/podman/argv.js
//   weakened  -- a hand-rolled argv with the protections deliberately removed
//
// The weakened posture is the negative control, and it is the most important thing in this
// directory. A green escape suite against a broken sandbox is worse than no suite at all, because
// it manufactures confidence. Note the weakened argv has to be hand-rolled precisely BECAUSE the
// builder refuses to emit it -- assertSafe() rejects bind mounts, --network host and friends. That
// refusal is itself part of what M0b bought us.
//
// Tier awareness matters here and is easy to get wrong. Under the microvm tier the guest runs its
// own kernel, so --cap-drop/seccomp do not constrain guest-side processes (measured: uid 0 with a
// full CapEff inside a krun guest). Asserting CapEff == 0 there would be a WRONG TEST, not a
// finding. So probes declare which tiers they are meaningful for, and the host-safety probes --
// the ones that actually matter -- apply to both.

const { spawn } = require('bare-subprocess')
const fs = require('bare-fs')
const path = require('bare-path')
const env = require('bare-env')
const argvlib = require('../../lib/isolation/podman/argv.js')

const IMAGE_REF = 'docker.io/library/ubuntu'
const IMAGE_TAG = '24.04'
const PROFILE = path.resolve('etc/seccomp/build-v1.json')
const CANARY_NAME = '.bw-escape-canary'
const CANARY_TEXT = 'CANARY-c7f3a91b2e5d4086-IF-YOU-SEE-THIS-THE-SANDBOX-LEAKED'

function sh(file, args, { timeoutMs = 120000, hostEnv = null } = {}) {
  return new Promise((resolve) => {
    let proc
    try {
      proc = spawn(file, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: hostEnv || { PATH: '/usr/local/bin:/usr/bin:/bin' }
      })
    } catch (err) {
      return resolve({ code: -1, stdout: '', stderr: String(err), spawnFailed: true })
    }
    let stdout = ''
    let stderr = ''
    let killed = false
    const timer = setTimeout(() => {
      killed = true
      try {
        proc.kill('SIGKILL')
      } catch {}
    }, timeoutMs)
    proc.stdout.on('data', (c) => {
      stdout += c
    })
    proc.stderr.on('data', (c) => {
      stderr += c
    })
    proc.on('error', (err) => {
      clearTimeout(timer)
      resolve({ code: -1, stdout, stderr: String(err) })
    })
    proc.on('exit', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr, killed })
    })
  })
}

async function probeEnvironment() {
  const v = await sh('podman', ['version', '--format', '{{.Client.Version}}'], { timeoutMs: 20000 })
  if (v.code !== 0) return { ok: false, why: 'podman unavailable' }
  const d = await sh(
    'podman',
    ['image', 'inspect', `${IMAGE_REF}:${IMAGE_TAG}`, '--format', '{{.Digest}}'],
    { timeoutMs: 30000 }
  )
  if (d.code !== 0) return { ok: false, why: `${IMAGE_REF}:${IMAGE_TAG} not present locally` }
  const digest = d.stdout.trim()

  // Is the microvm tier actually usable right now?
  const k = await sh(
    'podman',
    [
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
    ],
    { timeoutMs: 90000, hostEnv: argvlib.requiredHostEnv({ scope: false }, env) }
  )

  return { ok: true, digest, microvm: k.code === 0 }
}

// --- the host-side canary --------------------------------------------------------------
// A uniquely-marked, world-readable file in $HOME. World-readable on purpose: under --userns=auto
// the host uid is unmapped, so a bind-mounted file shows up as `nobody` -- mode 0644 means a leak
// would still be READABLE, which is the case we want to be able to detect.

function canaryPath() {
  return path.join(env.HOME || '/tmp', CANARY_NAME)
}

function plantCanary() {
  const p = canaryPath()
  fs.writeFileSync(p, CANARY_TEXT + '\n', { mode: 0o644 })
  return p
}

function removeCanary() {
  try {
    fs.unlinkSync(canaryPath())
  } catch {}
}

// --- postures ---------------------------------------------------------------------------

function hardenedSpec(tier, digest, extra = {}) {
  return {
    jobId: 'bwesc-' + tier,
    tier,
    image: { ref: IMAGE_REF, digest },
    seccompProfile: PROFILE,
    agent: '/bin/bash',
    scope: false, // the scope adds an orthogonal failure mode; covered by test/argv-runs.js
    ...extra
  }
}

async function runHardened(tier, digest, script, opts = {}) {
  const spec = hardenedSpec(tier, digest, opts.spec)
  const built = argvlib.build(spec)
  const args = [...built.args, '-lc', script]
  const res = await sh(built.program, args, {
    timeoutMs: opts.timeoutMs || 120000,
    hostEnv: argvlib.requiredHostEnv(spec, env)
  })
  return { ...res, posture: 'hardened', tier, argv: built.argv }
}

// The deliberately-broken control. Everything M0b added is stripped: default seccomp, no
// cap-drop, host uid mapped straight through, rootless network up, and $HOME bind-mounted in.
// This argv could not come from build() -- assertSafe() throws on most of it.
async function runWeakened(digest, script, opts = {}) {
  const home = env.HOME || '/tmp'
  const args = [
    'run',
    '--rm',
    '-i',
    '--log-driver',
    'none',
    '--network',
    'pasta', //            was: --network none
    //                                  no --userns flag: podman's rootless default maps the host
    //                                  uid to container root, so this runs privileged AND with
    //                                  the host uid mapped in. (--userns keep-id would run as the
    //                                  unprivileged host user and hold no capabilities, which
    //                                  made the capability arm of the control vacuous.)
    '--security-opt',
    'seccomp=unconfined', // was: our generated profile
    //                                  and: no --cap-drop, no --no-new-privileges,
    //                                  no --read-only, no --pids-limit
    '-v',
    `${home}:/host:ro`, //         was: no bind mounts at all
    '--entrypoint',
    '/bin/bash',
    `${IMAGE_REF}@${digest}`,
    '-lc',
    script
  ]
  const res = await sh('podman', args, {
    timeoutMs: opts.timeoutMs || 120000,
    hostEnv: argvlib.requiredHostEnv({ scope: false }, env)
  })
  return { ...res, posture: 'weakened', tier: 'container', argv: ['podman', ...args] }
}

module.exports = {
  sh,
  probeEnvironment,
  plantCanary,
  removeCanary,
  canaryPath,
  runHardened,
  runWeakened,
  hardenedSpec,
  CANARY_TEXT,
  CANARY_NAME,
  IMAGE_REF,
  IMAGE_TAG,
  PROFILE
}
