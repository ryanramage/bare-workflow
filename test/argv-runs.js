'use strict'

// Integration test: the argv the builder generates must actually RUN.
//
// The unit tests prove the argv says what we intend; they cannot prove podman accepts it. This
// gap is not hypothetical -- it is how the `--dns=none` conflict was found ("Error: conflicting
// options: dns and the network mode: none"), which every unit test happily approved.
//
// Skips cleanly when podman or the test image is unavailable, so it does not wedge CI on a
// machine without a container runtime.

const test = require('brittle')
const { spawn } = require('bare-subprocess')
const path = require('bare-path')
const argvlib = require('../lib/isolation/podman/argv.js')

const IMAGE_REF = 'docker.io/library/ubuntu'
const PROFILE = path.resolve('etc/seccomp/build-v1.json')

function sh(file, args, timeoutMs = 180000, env = null) {
  return new Promise((resolve) => {
    let proc
    try {
      proc = spawn(file, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: env || { PATH: '/usr/bin:/bin' }
      })
    } catch (err) {
      return resolve({ code: -1, stdout: '', stderr: String(err) })
    }
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
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
      resolve({ code, stdout, stderr })
    })
  })
}

async function probe() {
  const v = await sh('podman', ['version', '--format', '{{.Client.Version}}'], 20000)
  if (v.code !== 0) return { ok: false, why: 'podman unavailable' }
  const d = await sh(
    'podman',
    ['image', 'inspect', IMAGE_REF + ':24.04', '--format', '{{.Digest}}'],
    30000
  )
  if (d.code !== 0) return { ok: false, why: `${IMAGE_REF}:24.04 not present locally` }
  return { ok: true, digest: d.stdout.trim() }
}

// Build a spec that runs `sh -c <script>` instead of the real agent, so we can assert on output
// without needing the agent image built yet.
function specFor(tier, digest, extra = {}) {
  return {
    jobId: 'bwtest-' + tier,
    tier,
    image: { ref: IMAGE_REF, digest },
    seccompProfile: PROFILE,
    agent: '/bin/sh',
    scope: false, // systemd-run adds a second failure mode; covered separately below
    ...extra
  }
}

async function runSpec(spec, script) {
  const built = argvlib.build(spec)
  // The builder ends the argv with the image; step commands are appended as data, never
  // interpolated into a host shell.
  const args = [...built.args, '-c', script]
  // Explicit client-side allowlist -- never the ambient environment.
  const env = argvlib.requiredHostEnv(spec, require('bare-env'))
  return { built, result: await sh(built.program, args, 180000, env) }
}

test('generated argv runs: container tier', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  const { result } = await runSpec(specFor('container', p.digest), 'echo alive; id -u')
  t.is(result.code, 0, 'podman accepted every flag we generate\n' + result.stderr)
  t.ok(result.stdout.includes('alive'), 'workload ran')
  t.ok(result.stdout.includes('1000'), 'runs as uid 1000, not container-root')
})

test('generated argv runs: microvm tier', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  const { result } = await runSpec(specFor('microvm', p.digest), 'uname -r')
  if (result.code !== 0 && /krun|libkrun|kvm/i.test(result.stderr)) {
    t.comment('skipping: microvm tier unavailable -- ' + result.stderr.trim().split('\n')[0])
    t.pass('skipped')
    return
  }
  t.is(result.code, 0, 'podman accepted the krun annotation form\n' + result.stderr)
  // The guest runs its own kernel; that difference IS the security boundary for this tier.
  t.absent(
    result.stdout.includes('cachyos'),
    'guest kernel is not the host kernel: ' + result.stdout.trim()
  )
})

test('generated argv runs under a systemd scope', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  const { result } = await runSpec(specFor('container', p.digest, { scope: true }), 'echo scoped')
  if (result.code !== 0 && /systemd-run|dbus|scope/i.test(result.stderr)) {
    t.comment(
      'skipping: systemd --user scope unavailable -- ' + result.stderr.trim().split('\n')[0]
    )
    t.pass('skipped')
    return
  }
  t.is(result.code, 0, 'systemd-run wrapper is well formed\n' + result.stderr)
  t.ok(result.stdout.includes('scoped'))
})

test('the seccomp profile does not break ordinary tool use', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  // Exercises fork/clone heavily. If clone3 returned EPERM instead of ENOSYS, or the clone mask
  // were wrong, this is where it shows up.
  const script = 'for i in 1 2 3; do (echo sub-$i); done; seq 1 500 | wc -l'
  const { result } = await runSpec(specFor('container', p.digest), script)
  t.is(result.code, 0, 'subshells and pipelines work under the profile\n' + result.stderr)
  t.ok(result.stdout.includes('sub-3'), 'fork path intact')
  t.ok(result.stdout.includes('500'), 'pipeline path intact')
})

test('the seccomp profile denies the namespace syscalls', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  // Container tier only: under microvm the guest has its own kernel, so guest-side caps and
  // syscall filters say nothing about host safety. Asserting this there would be a wrong test.
  const { result } = await runSpec(
    specFor('container', p.digest),
    'unshare -Ur true 2>&1; echo rc=$?'
  )
  t.not(result.stdout.trim(), 'rc=0', 'unshare must not succeed: ' + JSON.stringify(result.stdout))
  t.ok(/not permitted|rc=[1-9]/.test(result.stdout), 'unshare refused: ' + result.stdout.trim())
})
