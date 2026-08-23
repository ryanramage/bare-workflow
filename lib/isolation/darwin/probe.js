'use strict'

// Can this machine run a build under Seatbelt, natively, and sign the result?
//
// This is the tier that exists to produce `darwin-arm64` -- the one target a Linux runner cannot
// close, because `codesign` does not exist in a Linux guest. Everything here is a question about the
// HOST, not about a container runtime, which is why it does not live under podman/.
//
// All four checks, not just the first. A machine with `sandbox-exec` but no Command Line Tools would
// otherwise pass the probe and fail deep inside packaging with a missing `codesign`, which reads as a
// bug in the build rather than a missing dependency. The measured facts behind them:
//
//   * `sandbox-exec` is present on every macOS install (it is formally deprecated as of 10.14 and
//     entirely functional; Nix and Bazel both ship on it).
//   * `codesign` and a real CLT are what produce a RUNNABLE arm64 Mach-O. Measured: with no `--sign`
//     flag bare-build emits an ad-hoc signature (`Signature=adhoc`), which is all Apple Silicon
//     requires to execute a binary -- no certificate, no Apple ID, no notarization.
//   * The profile has to exist, because `sandbox-exec -f` cannot run without one. That check is also
//     what keeps this tier honestly unavailable while it is being built: an available tier with no
//     confinement document is the one outcome decision 3 forbids.

const os = require('bare-os')
const fs = require('bare-fs')
const { spawnSync } = require('bare-subprocess')

const { hostEnv, which } = require('./../../host-env.js')

// The tools, in the order their absence is most likely and most confusing.
const TOOLS = [
  {
    bin: 'sandbox-exec',
    why: 'Seatbelt confinement',
    fix: 'sandbox-exec ships with macOS; a missing one means something is very wrong with this host'
  },
  {
    bin: 'codesign',
    why: 'ad-hoc signing, without which an arm64 Mach-O will not execute',
    fix: 'xcode-select --install'
  }
]

function probe(opts = {}) {
  const platform = opts.platform || os.platform()
  const profile = opts.profile || null

  if (platform !== 'darwin') {
    return {
      available: false,
      reason: `Seatbelt is macOS-only and this host is ${platform}`,
      // No remediation: this is not a missing dependency, it is the wrong machine. Offering a fix
      // here would be the `pacman -S libkrun` mistake in the other direction.
      remediation: null
    }
  }

  for (const tool of TOOLS) {
    if (which(tool.bin) === null) {
      return {
        available: false,
        reason: `${tool.bin} not found -- needed for ${tool.why}`,
        remediation: tool.fix
      }
    }
  }

  // `codesign` existing is not the same as the toolchain being usable: the stub at /usr/bin/codesign
  // is present even with no Command Line Tools installed, and only fails when invoked.
  const clt = spawnSync('xcode-select', ['-p'], { env: hostEnv() })
  if (clt.status !== 0) {
    return {
      available: false,
      reason: 'no Xcode Command Line Tools -- codesign is a stub without them',
      remediation: 'xcode-select --install'
    }
  }

  if (!profile) {
    return {
      available: false,
      reason: 'no Seatbelt profile was supplied to the probe',
      remediation: 'this is a programming error; the caller must pass one'
    }
  }
  if (!exists(profile)) {
    return {
      available: false,
      reason: `Seatbelt profile missing at ${profile}`,
      remediation: 'bare scripts/build/sandbox.js'
    }
  }

  return {
    available: true,
    reason: null,
    remediation: null,
    developerDir: (clt.stdout ? clt.stdout.toString() : '').trim()
  }
}

function exists(path) {
  try {
    fs.statSync(path)
    return true
  } catch {
    return false
  }
}

module.exports = { probe, TOOLS }
