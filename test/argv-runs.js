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
const bareEnv = require('bare-env')
const os = require('bare-os')
const argvlib = require('../lib/isolation/podman/argv.js')
const { hostEnv, which } = require('../lib/host-env.js')

const IMAGE_REF = 'docker.io/library/ubuntu'
const PROFILE = path.resolve('etc/seccomp/build-v1.json')

// The last-resort PATH if the real one is somehow absent. Homebrew on Apple Silicon is
// /opt/homebrew/bin and the official macOS podman installer uses /opt/podman/bin -- neither is in
// the usual POSIX default. Without them `podman` is unresolvable, every probe reports "podman
// unavailable", and the escape suite AND ITS NEGATIVE CONTROL pass while measuring nothing. Worse,
// it works on an Intel Mac (where /usr/local/bin IS the Homebrew prefix), so the suite would go
// vacuous on one machine and not another. Prefer the real PATH; the literal is only a fallback.
const PROBE_PATH = '/opt/homebrew/bin:/opt/podman/bin:/usr/local/bin:/usr/bin:/bin'

function sh(file, args, timeoutMs = 180000, env = null) {
  return new Promise((resolve) => {
    // Look before spawning. bare-subprocess throws ENOENT for a missing program AND the bare process
    // then exits 144 during teardown even though the throw is caught -- measured on macOS with
    // systemd-run. So spawning a known-absent binary turns a fully green suite into a non-zero exit,
    // and the thrown error carries no program name to diagnose it with.
    if (which(file, { PATH: bareEnv.PATH || PROBE_PATH }) === null) {
      return resolve({ code: -1, stdout: '', stderr: `${file} not found`, missing: true })
    }
    let proc
    try {
      proc = spawn(file, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: env || hostEnv(null, { PATH: bareEnv.PATH || PROBE_PATH, ...bareEnv })
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
  // `info`, not `version`: info asks the SERVER, which is what actually has to work, and it is the
  // only form that distinguishes "podman is not installed" from "podman is installed but its VM is
  // stopped". Reporting both as "podman unavailable" is how a whole suite skips for a reason nobody
  // can act on.
  const v = await sh('podman', ['info', '--format', '{{.Version.Version}}'], 20000)
  if (v.code !== 0) {
    const why = v.missing
      ? 'podman not found on PATH'
      : 'podman did not answer: ' + (v.stderr.trim().split('\n')[0] || `exit ${v.code}`)
    return { ok: false, why }
  }
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
  //
  // This used to match the literal string 'cachyos' -- the distro of the machine it was written on.
  // Vacuous on every other host, which is the same failure shape as the `ip route` probe recorded in
  // CLAUDE.md: a check that passes because it cannot fail. Compare against the real host kernel, and
  // skip rather than pass when the host will not tell us what that is.
  // `os.release()`, not `os.version()`: release is `uname -r` (7.2.0-1-cachyos), version is the
  // build banner (#1 SMP PREEMPT_DYNAMIC ...). Comparing against the banner would never match and
  // the assertion would pass for the wrong reason -- the same trap being fixed here.
  const hostKernel = os.release ? os.release() : ''
  const guestKernel = result.stdout.trim()
  if (!hostKernel || !guestKernel) {
    t.comment(`cannot compare kernels (host ${JSON.stringify(hostKernel)})`)
    return t.pass('skipped the kernel comparison')
  }
  t.not(guestKernel, hostKernel, `guest kernel ${guestKernel} is not the host's ${hostKernel}`)
  t.absent(hostKernel.startsWith(guestKernel), 'not merely a prefix of it either')
})

test('generated argv runs under a systemd scope', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  // systemd is Linux-only, and this is decided on the PLATFORM rather than on stderr text. The old
  // guard matched /systemd-run|dbus|scope/ against the failure message, but a missing binary throws
  // "no such file or directory" with no program name in it, so on macOS the guard missed and the
  // test failed loudly where it meant to skip.
  if (os.platform() !== 'linux') {
    t.comment(`skipping: systemd --user scopes are Linux-only and this host is ${os.platform()}`)
    t.comment('note this means scopeArgs() is unexercised here -- it is covered by test/argv.js')
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

test('the seccomp profile applies on THIS arch, not just x86', async (t) => {
  const p = await probe()
  if (!p.ok) {
    t.comment('skipping: ' + p.why)
    t.pass('skipped')
    return
  }

  // Why this exists, and why it is separate from the test above.
  //
  // etc/seccomp/build-v1.json declares only SCMP_ARCH_X86_64/X86/X32 -- no AARCH64. Reading
  // libseccomp suggests seccomp_init() always installs the NATIVE arch and `architectures` only ADDS
  // extra ones, so the filter should still apply on arm64. But CLAUDE.md is explicit that two audits
  // have already been wrong about seccomp in this project, so this is measured rather than reasoned.
  //
  // The test above cannot answer it: the hardened posture also passes --cap-drop ALL, and CLAUDE.md
  // records that `--cap-drop ALL` -- NOT seccomp -- is what blocks nested-userns escalation. So a
  // denied unshare there proves nothing about the syscall filter. This isolates seccomp by granting
  // FULL capabilities and varying only the profile, and pairs it with an unconfined control so a
  // vacuous pass is impossible: if the control stops succeeding, the measurement is meaningless.
  const script =
    'unshare -Ur true; echo "unshare_rc=$?"; ' +
    'mkdir -p /tmp/m; mount -t tmpfs none /tmp/m 2>/dev/null; echo "mount_rc=$?"; ' +
    '/bin/echo alive'

  const base = [
    'run',
    '--rm',
    '--network',
    'none',
    '--log-driver',
    'none',
    '--cap-add',
    'ALL', // deliberately NOT cap-drop: we are measuring seccomp alone
    '--entrypoint',
    '/bin/sh'
  ]
  const img = `${IMAGE_REF}@${p.digest}`

  const filtered = await sh('podman', [
    ...base,
    '--security-opt',
    `seccomp=${PROFILE}`,
    img,
    '-c',
    script
  ])
  const control = await sh('podman', [
    ...base,
    '--security-opt',
    'seccomp=unconfined',
    img,
    '-c',
    script
  ])

  // The control first: without it, "blocked" could just mean "the container never ran".
  t.ok(/unshare_rc=0/.test(control.stdout), 'CONTROL: unconfined lets unshare succeed')
  t.ok(/mount_rc=0/.test(control.stdout), 'CONTROL: unconfined lets mount succeed')

  t.absent(/unshare_rc=0/.test(filtered.stdout), 'the profile denies unshare on ' + os.arch())
  t.absent(/mount_rc=0/.test(filtered.stdout), 'the profile denies mount on ' + os.arch())

  // And it is a syscall filter, not a broken container: ordinary tooling still runs. This is the
  // other half of blocker 4 -- the x86-only names in the profile (modify_ldt, iopl, ioperm,
  // arch_prctl) resolve to -EDOM on aarch64, and if crun errored on them the container would not
  // start at all rather than starting with a working filter.
  t.ok(/alive/.test(filtered.stdout), 'and ordinary tools still work under it')
})
