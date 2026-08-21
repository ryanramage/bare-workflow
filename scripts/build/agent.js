// Builds the standalone agent binary, then the sandbox base image with the agent baked in.
//
// The agent MUST be baked into the image: there are no bind mounts available to inject it (rootless
// idmapped mounts are kernel-forbidden, and we refuse host mounts anyway), and a krun microVM
// cannot be `podman exec`'d to drop it in afterwards.
//
// Usage: bare scripts/build/agent.js [--skip-binary] [--tag localhost/bare-workflow-base:dev]

const { spawn } = require('bare-subprocess')
const fs = require('bare-fs')
const path = require('bare-path')
const env = require('bare-env')

const ROOT = path.join(__dirname, '../..')
const OUT = path.join(ROOT, 'out/agent')
const BINARY = path.join(OUT, 'bw-agent')

function argOf(flag, dflt) {
  const i = Bare.argv.indexOf(flag)
  return i === -1 ? dflt : Bare.argv[i + 1]
}
const has = (flag) => Bare.argv.includes(flag)

const TAG = argOf('--tag', 'localhost/bare-workflow-base:dev')
const HOST = argOf('--host', 'linux-x64')

function run(file, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(file, args, {
      cwd: ROOT,
      stdio: ['ignore', 'inherit', 'inherit'],
      env: { PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR },
      ...opts
    })
    proc.on('error', reject)
    proc.on('exit', (code) =>
      code === 0 ? resolve() : reject(new Error(`${file} exited ${code}`))
    )
  })
}

async function main() {
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

  console.log(`building image ${TAG}...`)
  await run('podman', ['build', '-f', 'etc/Containerfile', '-t', TAG, '.'])

  console.log(`\ndone. image: ${TAG}`)
  console.log('resolve its digest with:')
  console.log(`  podman image inspect ${TAG} --format '{{.Digest}}'`)
}

main().catch((err) => {
  console.error('build failed:', err.message)
  Bare.exitCode = 1
})
