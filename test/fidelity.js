// M0a fidelity spike.
//
// The whole driver design rides on one assumption: `podman run -i` (no TTY) gives us
// byte-exact, stream-separated, backpressured stdout/stderr over plain pipes. crun's krun
// handler has no `exec`, so a long-lived agent on fd 0/1 is the ONLY seam available -- if
// podman's non-TTY attach mangles bytes or interleaves the streams, the entire architecture
// has to change. So we prove it before writing any of it.
//
// Run: bare scratch/fidelity.js [--image ubuntu:24.04] [--mb 64]

const { spawn } = require('bare-subprocess')
const crypto = require('bare-crypto')

const IMAGE = argOf('--image', 'docker.io/library/ubuntu:24.04')
const MB = Number(argOf('--mb', '64'))

function argOf(flag, dflt) {
  const i = Bare.argv.indexOf(flag)
  return i === -1 ? dflt : Bare.argv[i + 1]
}

// Hardened-ish flags: enough to prove the streams work under the posture we actually plan to
// use, rather than proving it for a permissive container and being surprised later.
function podmanArgs(script) {
  return [
    'run',
    '--rm',
    '-i',
    '--network',
    'none',
    '--userns',
    'auto',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--read-only',
    '--read-only-tmpfs=false',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,size=1g,mode=1777',
    '--pids-limit',
    '512',
    '--memory',
    '2g',
    '--log-driver',
    'none',
    '--entrypoint',
    '/bin/sh',
    IMAGE,
    '-c',
    script
  ]
}

function run(script, { onStdout, onStderr, pauseMs = 0 } = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn('podman', podmanArgs(script), {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: '/usr/bin:/bin' } // never inherit our env into the podman client
    })

    let outBytes = 0
    let errBuf = ''

    proc.stdout.on('data', (c) => {
      outBytes += c.byteLength
      onStdout && onStdout(c)
    })
    proc.stderr.on('data', (c) => {
      errBuf += c.toString()
      onStderr && onStderr(c)
    })

    if (pauseMs > 0) {
      // Stop reading entirely for a while. If the pipe applies backpressure the child simply
      // blocks and we lose nothing; if it drops or truncates, the hash check downstream fails.
      proc.stdout.pause()
      setTimeout(() => proc.stdout.resume(), pauseMs)
    }

    proc.on('error', reject)
    proc.on('exit', (code, signal) => {
      resolve({ code, signal, outBytes, errBuf })
    })
  })
}

const results = []
function check(name, ok, detail) {
  results.push({ name, ok, detail })
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${name}${detail ? '  -- ' + detail : ''}`)
}

async function main() {
  console.log(`image=${IMAGE} payload=${MB}MiB\n`)

  // --- 1. byte-exactness + stream separation, in one shot -------------------------------
  // The container hashes the payload itself and reports the digest on stderr while the raw
  // bytes go to stdout. Comparing the two proves stdout was not mangled AND that the digest
  // never leaked into the byte stream.
  {
    const hash = crypto.createHash('sha256')
    const script =
      `dd if=/dev/urandom of=/tmp/p bs=1M count=${MB} status=none && ` +
      `sha256sum /tmp/p | cut -d' ' -f1 >&2 && cat /tmp/p`

    const r = await run(script, { onStdout: (c) => hash.update(c) })
    const got = hash.digest('hex')
    const want = r.errBuf.trim()

    check('exit 0', r.code === 0, `code=${r.code} signal=${r.signal}`)
    check('stdout byte count', r.outBytes === MB * 1024 * 1024, `${r.outBytes} bytes`)
    check(
      'stdout byte-exact (sha256)',
      got === want && want.length === 64,
      `in=${want.slice(0, 16)} out=${got.slice(0, 16)}`
    )
    check(
      'stderr carried only the digest',
      /^[0-9a-f]{64}$/.test(want),
      JSON.stringify(r.errBuf.slice(0, 80))
    )
  }

  // --- 2. separation under heavy interleaving -------------------------------------------
  // Alternating writes to both fds. Any cross-contamination shows up as an OUT marker in
  // stderr or an ERR marker in stdout.
  {
    const N = 2000
    const script = `i=0; while [ $i -lt ${N} ]; do echo "OUT-$i"; echo "ERR-$i" >&2; i=$((i+1)); done`
    let out = ''
    const r = await run(script, {
      onStdout: (c) => {
        out += c.toString()
      }
    })

    const outHasErr = out.includes('ERR-')
    const errHasOut = r.errBuf.includes('OUT-')
    const outCount = (out.match(/OUT-/g) || []).length
    const errCount = (r.errBuf.match(/ERR-/g) || []).length

    check('no stderr bleed into stdout', !outHasErr)
    check('no stdout bleed into stderr', !errHasOut)
    check('all stdout lines present', outCount === N, `${outCount}/${N}`)
    check('all stderr lines present', errCount === N, `${errCount}/${N}`)
  }

  // --- 3. backpressure: refuse to read for 2s, then drain ------------------------------
  // Proves the pipe blocks the producer rather than dropping or truncating data.
  {
    const hash = crypto.createHash('sha256')
    const script =
      `dd if=/dev/urandom of=/tmp/q bs=1M count=${MB} status=none && ` +
      `sha256sum /tmp/q | cut -d' ' -f1 >&2 && cat /tmp/q`
    const r = await run(script, { onStdout: (c) => hash.update(c), pauseMs: 2000 })
    const got = hash.digest('hex')
    const want = r.errBuf.trim()
    check(
      'backpressure loses nothing',
      got === want && r.outBytes === MB * 1024 * 1024,
      `${r.outBytes} bytes, hash ${got === want ? 'match' : 'MISMATCH'}`
    )
  }

  const failed = results.filter((r) => !r.ok)
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
  if (failed.length) {
    console.log('\nM0a GATE FAILED -- the agent-over-stdio design needs rework:')
    for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`)
    Bare.exitCode = 1
  } else {
    console.log('M0a gate passed: agent-over-stdio is viable.')
  }
}

main().catch((err) => {
  console.error('spike error:', err)
  Bare.exitCode = 1
})
