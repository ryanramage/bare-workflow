'use strict'

// Regenerate etc/seccomp/build-v1.json from a PINNED base profile, and capture that pin.
//
// Why the base is pinned rather than read from whatever machine you happen to be on.
//
// `generate()` starts from the container host's containers-common profile
// (/usr/share/containers/seccomp.json) and hardens it. That file is NOT the same everywhere, and the
// differences are not cosmetic. Measured between an Arch host and the Fedora CoreOS guest inside a
// macOS podman machine -- 448 syscalls compared, 6 disagreed:
//
//   * `socket` with arg0 == 40 (AF_VSOCK) is DENIED via the Arch base and absent from the CoreOS
//     one. AF_VSOCK is the host<->guest channel; losing that restriction is a real weakening, and it
//     would have happened silently just by running the generator on a Mac.
//   * `futex_wait`, `futex_wake`, `futex_requeue`, `futex_waitv` and `fanotify_init` are allowed by
//     the Arch base and unlisted in the CoreOS one, so they would fall through to the default ERRNO.
//     Denying the futex family with EPERM is the same hazard as the clone3 bug this generator's
//     tests were written around: it breaks threading in ways that present as "npm hangs forever".
//
// So "run the generator and commit the result" is only reproducible against a fixed base. The base
// is committed next to the output, the generator reads the committed base by default, and the drift
// guard in test/seccomp.js compares against that -- which means it tests what it means to test (did
// someone change the generator without regenerating?) instead of testing which distro you are on.
//
//   bare scripts/build/seccomp.js              # regenerate build-v1.json from the pinned base
//   bare scripts/build/seccomp.js --check      # exit 1 if the committed output is stale
//   bare scripts/build/seccomp.js --capture    # refresh the pinned base from THIS container host
//
// --capture is the deliberate act of adopting a new upstream base. Review its diff: it is the input
// to a security-critical artifact, and the two bullets above are what a careless bump looks like.

const fs = require('fs')
const path = require('path')
const { spawnSync } = require('subprocess')

const seccomp = require('../../lib/isolation/podman/seccomp.js')
const { hostEnv, which } = require('../../lib/host-env.js')

const ROOT = path.join(__dirname, '..', '..')
const BASE_PIN = path.join(ROOT, 'etc/seccomp/base-v1.json')
const OUTPUT = path.join(ROOT, 'etc/seccomp/build-v1.json')
const HOST_BASE = '/usr/share/containers/seccomp.json'

const argv = Bare.argv.slice(2)
const has = (f) => argv.includes(f)

// Read the base from whichever machine actually runs containers. On Linux that is this host; on
// macOS and Windows podman is a remote client and the file lives inside the podman-machine VM.
function readLiveBase() {
  try {
    return fs.readFileSync(HOST_BASE, 'utf8')
  } catch {}
  if (!which('podman')) return null
  const r = spawnSync('podman', ['machine', 'ssh', 'cat ' + HOST_BASE], { env: hostEnv() })
  if (r.status !== 0 || !r.stdout) return null
  return r.stdout.toString()
}

function loadPin() {
  try {
    return seccomp.assertBase(JSON.parse(fs.readFileSync(BASE_PIN, 'utf8')))
  } catch {
    return null
  }
}

function main() {
  if (has('--capture')) {
    const raw = readLiveBase()
    if (!raw) {
      console.error(
        `cannot read ${HOST_BASE} on this host, and no podman machine could supply it.\n` +
          'On Linux: install containers-common. On macOS/Windows: podman machine start.'
      )
      Bare.exitCode = 1
      return
    }
    const doc = seccomp.assertBase(JSON.parse(raw))
    fs.writeFileSync(BASE_PIN, JSON.stringify(doc, null, 2) + '\n')
    console.log(`captured base -> ${path.relative(ROOT, BASE_PIN)}`)
    console.log('review the diff, then regenerate: bare scripts/build/seccomp.js')
    return
  }

  const base = loadPin()
  if (!base) {
    console.error(
      `no pinned base at ${path.relative(ROOT, BASE_PIN)}.\n` +
        'Capture one on the machine whose base produced the committed profile:\n' +
        '  bare scripts/build/seccomp.js --capture'
    )
    Bare.exitCode = 1
    return
  }

  const expected = seccomp.serialize(seccomp.generate({ base }))

  if (has('--check')) {
    let committed = null
    try {
      committed = fs.readFileSync(OUTPUT, 'utf8')
    } catch {}
    if (committed === expected) {
      console.log('up to date')
      return
    }
    console.error('etc/seccomp/build-v1.json is stale -- run: bare scripts/build/seccomp.js')
    Bare.exitCode = 1
    return
  }

  fs.writeFileSync(OUTPUT, expected)
  console.log(`wrote ${path.relative(ROOT, OUTPUT)} from ${path.relative(ROOT, BASE_PIN)}`)
}

main()
