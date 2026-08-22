// Builds the standalone agent binary, then the sandbox base image with the agent baked in.
//
// The agent MUST be baked into the image: there are no bind mounts available to inject it (rootless
// idmapped mounts are kernel-forbidden, and we refuse host mounts anyway), and a krun microVM
// cannot be `podman exec`'d to drop it in afterwards.
//
// Usage: bare scripts/build/agent.js [--skip-binary] [--tag localhost/bare-workflow-base:dev]

const { spawn, spawnSync } = require('bare-subprocess')
const fs = require('bare-fs')
const path = require('bare-path')
const { hostEnv, which } = require('../../lib/host-env.js')
const os = require('bare-os')

const ROOT = path.join(__dirname, '../..')
const OUT = path.join(ROOT, 'out/agent')
const BINARY = path.join(OUT, 'bw-agent')

function argOf(flag, dflt) {
  const i = Bare.argv.indexOf(flag)
  return i === -1 ? dflt : Bare.argv[i + 1]
}
const has = (flag) => Bare.argv.includes(flag)

const TAG = argOf('--tag', 'localhost/bare-workflow-base:dev')

// ELF e_machine values, read straight from the binary. Cheaper and more portable than shelling to
// `file(1)`, and this has to work on a Mac where `file` output differs.
const ELF_MACHINE = { 0x3e: 'x64', 0xb7: 'arm64' }

// The agent's architecture must match the machine that will RUN it, which is the podman server --
// not this host. On Linux those are the same and the distinction never mattered. On Apple Silicon
// they differ: `podman machine` runs an aarch64 Linux guest, `FROM ubuntu:24.04` resolves to the
// arm64 manifest, and an x86-64 agent baked into it is an `exec format error` at
// `--entrypoint /opt/bw/agent`. That surfaces as `podman exited 126` from the launcher -- a
// launcher problem, not an architecture one -- so it is worth detecting up front.
//
// Note this cannot be fixed by enabling Rosetta or qemu in the machine: emulation is refused
// outright by this project. The agent is cross-BUILT instead, which bare-build does natively.
function serverArch() {
  const info = spawnSync('podman', ['info', '--format', '{{.Host.Arch}}'], {
    env: hostEnv()
  })
  const arch = info.status === 0 && info.stdout ? info.stdout.toString().trim() : ''
  // podman reports Go arch names.
  if (arch === 'arm64' || arch === 'aarch64') return 'arm64'
  if (arch === 'amd64' || arch === 'x86_64') return 'x64'
  return null
}

const SERVER_ARCH = serverArch()

function defaultHost() {
  const explicit = argOf('--host', null)
  if (explicit) return explicit
  if (SERVER_ARCH) return 'linux-' + SERVER_ARCH
  const fallback = 'linux-' + os.arch()
  console.log(
    `could not read the podman server arch; assuming ${fallback}. Pass --host to be explicit.`
  )
  return fallback
}

const HOST = defaultHost()
const CROSS = has('--cross')

function run(file, args, opts = {}) {
  return new Promise((resolve, reject) => {
    // Look before spawning. bare-subprocess throws ENOENT for a missing program and the bare process
    // then exits 144 during teardown regardless -- so a missing `bare-build` produced exit 144 with
    // NO output at all, which is about as unhelpful as a build failure gets. The thrown error does
    // not name the program either, so the message has to be built here.
    if (which(file) === null) {
      return reject(
        new Error(
          `${file} is not on PATH.` +
            (file === 'bare-build' ? ' Install it with: npm i -g bare-build' : '')
        )
      )
    }
    const proc = spawn(file, args, {
      cwd: ROOT,
      stdio: ['ignore', 'inherit', 'inherit'],
      env: hostEnv(),
      ...opts
    })
    proc.on('error', reject)
    proc.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`${file} exited ${code}`))
    )
  })
}

async function main() {
  // Refuse BEFORE building, not after: the build takes about a minute and leaves the wrong binary at
  // out/agent/bw-agent, so a late refusal costs the time AND hands the next invocation a mismatched
  // binary to trip over.
  const wanted = HOST.startsWith('linux-') ? HOST.slice('linux-'.length) : null
  if (wanted && SERVER_ARCH && wanted !== SERVER_ARCH && !CROSS) {
    console.error(`REFUSING: --host ${HOST} but this podman server runs linux-${SERVER_ARCH}.`)
    console.error('  Baking in an agent for the wrong architecture fails at step time as')
    console.error('  `podman exited 126` (exec format error), which reads as a launcher bug.')
    console.error(
      `\n  For this machine:      bare scripts/build/agent.js --host linux-${SERVER_ARCH}`
    )
    console.error('  Deliberate cross-build: add --cross (the image will not run here)')
    Bare.exitCode = 1
    return
  }

  if (!has('--skip-binary')) {
    console.log(`building agent binary (${HOST})...`)
    // NOTE: do NOT strip the result. bare-build embeds the JS bundle in the executable in a way
    // that `strip` destroys -- a stripped binary segfaults immediately. Measured: 84 MB unstripped
    // works, 64 MB stripped core-dumps. The size is fine; it lands in a cached image layer.
    await run('bare-build', [
      '--standalone',
      '--base',
      '.',
      '--name',
      'bw-agent',
      '--host',
      HOST,
      '--out',
      'out/agent',
      'lib/agent/bin.js'
    ])
  }

  const stat = fs.statSync(BINARY)
  console.log(`agent binary: ${BINARY} (${(stat.size / 1e6).toFixed(1)} MB)`)

  // Architecture guard, in the same spirit as the staleness guard below: the binary is opaque once
  // it is inside an image, so check it here where the error can still name the fix.
  //
  // Compared against the SERVER. This is the belt-and-braces half, and it is the `--skip-binary`
  // path that needs it: a binary left over from an earlier cross-build would otherwise be baked in
  // silently, since the early check above only sees the flags.
  const built = elfArch(BINARY)
  if (built && wanted && built !== wanted) {
    console.error(`\nREFUSING: asked for linux-${wanted} but the binary on disk is ${built}.`)
    console.error('  Rebuild without --skip-binary.')
    Bare.exitCode = 1
    return
  }
  if (built && SERVER_ARCH && built !== SERVER_ARCH && !CROSS) {
    console.error(
      `\nREFUSING: the agent binary is ${built} but this podman server runs ${SERVER_ARCH}.`
    )
    console.error('  Baking it in would fail at step time as `podman exited 126` (exec format')
    console.error('  error), which reads as a launcher bug rather than an architecture one.')
    console.error(
      `\n  For this machine:      bare scripts/build/agent.js --host linux-${SERVER_ARCH}`
    )
    console.error('  Deliberate cross-build: add --cross (the image will not run here)')
    Bare.exitCode = 1
    return
  }
  if (built && SERVER_ARCH && built !== SERVER_ARCH) {
    console.log(`cross-building: ${built} agent for a ${SERVER_ARCH} server (--cross given)`)
  }

  // Staleness guard. --skip-binary is convenient and it is also a trap: a stale binary baked into
  // a fresh image fails in ways that look like code bugs. It cost real time once already -- the
  // agent lacked ensureWorkspace(), every step died with "working directory does not exist: /w/src",
  // and the obvious suspect was the workdir change made in the same sitting.
  const sources = [
    'lib/agent/bin.js',
    'lib/agent/index.js',
    'lib/protocol.js',
    'schema/spec/hrpc/index.js',
    'schema/spec/hrpc/messages.js'
  ]
  const newer = sources.filter((rel) => {
    try {
      return fs.statSync(path.join(ROOT, rel)).mtimeMs > stat.mtimeMs
    } catch {
      return false
    }
  })
  if (newer.length) {
    console.error('\nREFUSING: the agent binary is older than its sources:')
    for (const rel of newer) console.error('  ' + rel)
    console.error('\nRebuild it (drop --skip-binary), or the image will ship stale code.')
    Bare.exitCode = 1
    return
  }

  // A cross-build stops at the binary, deliberately. Building the IMAGE here would produce
  // something misleading: `FROM ubuntu:24.04` resolves to the manifest for THIS host, so an x64
  // machine yields x64 Ubuntu layers with an arm64 agent inside -- an image that runs on neither
  // side. Making it genuinely arm64 would need `--platform linux/arm64`, and the Containerfile has
  // `RUN` steps, so that needs qemu. Emulation is refused outright by this project, so the honest
  // answer is: carry the binary over and build the image on the machine that will run it.
  if (CROSS) {
    console.log(`\ndone. binary only: ${BINARY} (${built || 'unknown arch'})`)
    console.log("\nNot building an image: `FROM ubuntu:24.04` would resolve to this host's arch,")
    console.log('and making it otherwise needs emulation. On the target machine:')
    console.log(`  copy this binary to out/agent/bw-agent, then`)
    console.log('  bare scripts/build/agent.js --skip-binary')
    return
  }

  console.log(`building image ${TAG}...`)
  await run('podman', ['build', '-f', 'etc/Containerfile', '-t', TAG, '.'])

  console.log(`\ndone. image: ${TAG}`)
  console.log('resolve its digest with:')
  console.log(`  podman image inspect ${TAG} --format '{{.Digest}}'`)
}

// Read e_machine from the ELF header. Returns null for anything that is not an ELF we know.
function elfArch(file) {
  let fd = null
  try {
    fd = fs.openSync(file, 'r')
    const head = Buffer.alloc(20)
    fs.readSync(fd, head, 0, 20, 0)
    if (head.toString('latin1', 0, 4) !== '\x7fELF') return null
    return ELF_MACHINE[head.readUInt16LE(18)] || null
  } catch {
    return null
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd)
      } catch {}
    }
  }
}

main().catch((err) => {
  console.error('build failed:', err.message)
  Bare.exitCode = 1
})
