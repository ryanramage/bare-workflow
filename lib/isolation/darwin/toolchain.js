'use strict'

// What the seatbelt tier lets a build READ.
//
// A container tier gets its toolchain from an image. A native one has to be told where THIS host
// keeps node, npm, bare-build and the Xcode tools, which makes this the one soft edge of an
// otherwise deny-by-default boundary -- so it lives in its own file, is kept as narrow as it can be,
// and every path it returns is recorded in the attestation.
//
// It is here rather than in bin.js so the escape suite can assert against the profile that actually
// ships, instead of a hand-written one that happens to be tighter.

const path = require('bare-path')
const env = require('bare-env')

const { hostEnv } = require('./../../host-env.js')

// Tools a native build reaches for. Resolved through their version-manager shim ON THE HOST, before
// the sandbox exists, because the shim cannot run inside it -- see resolveShims.
const NATIVE_TOOLS = ['node', 'npm', 'npx', 'bare', 'bare-build']

// Version-manager shims resolve to the real binary by consulting mutable state, and several of them
// take a lock to do it. Volta is the case measured here: `~/.volta/bin/bare-build` is a symlink to
// `volta-shim`, which needs to write `~/.volta/volta.lock` and fails inside the sandbox with
//
//   Volta error: Could not find executable "bare-build"
//   Volta error: Error cause: Resource temporarily unavailable (os error 35)
//
// Granting the sandbox write access to `~/.volta` would fix it and is exactly the wrong trade: a
// build could then replace a binary that later runs UNSANDBOXED, in a tier whose entire premise is
// that $HOME is unreachable. So the shim is resolved out here, where writing is allowed, and the
// sandbox gets the real directories instead. nvm, asdf and rbenv have the same shape.
function resolveShims() {
  const dirs = []
  const haveVolta = spawnSyncOut('volta', ['--version']) !== null
  for (const tool of NATIVE_TOOLS) {
    const real = haveVolta ? spawnSyncOut('volta', ['which', tool]) : null
    if (real && real.startsWith('/')) dirs.push(path.dirname(real))
  }
  return dirs
}

function seatbeltToolchain(opts = {}) {
  const out = new Set()

  // FIRST, so they take precedence on the step PATH over the shim directory they came from.
  for (const dir of resolveShims()) out.add(dir)
  // The runner's own code and runtime: the agent runs from source under the host `bare`.
  // The runner's own code: the agent runs from source under the host `bare`.
  out.add(opts.repo || path.join(__dirname, '../../..'))
  if (typeof Bare !== 'undefined' && Bare.argv[0]) out.add(path.dirname(Bare.argv[0]))

  // Whatever is on PATH, which is where the build's tools actually live. Directories only, and the
  // profile grants read, never write.
  for (const dir of (env.PATH || '').split(':')) {
    if (dir && dir.startsWith('/')) out.add(dir)
  }

  // Volta and Homebrew keep the real binaries behind their bin shims, so granting only the shim
  // directory is not enough.
  const home = env.HOME
  if (home) out.add(path.join(home, '.volta'))
  out.add('/opt/homebrew')
  out.add('/usr/local')

  // Xcode, for codesign -- the entire reason this tier exists.
  const dev = spawnSyncOut('xcode-select', ['-p'])
  if (dev) out.add(dev)

  return [...out]
}

function spawnSyncOut(file, args) {
  const { spawnSync } = require('bare-subprocess')
  try {
    const r = spawnSync(file, args, { env: hostEnv() })
    if (r.status !== 0) return null
    return (r.stdout ? r.stdout.toString() : '').trim() || null
  } catch {
    return null
  }
}

module.exports = { seatbeltToolchain, resolveShims, NATIVE_TOOLS }
