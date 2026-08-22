'use strict'

// Refuse to run an image built for an architecture the container runtime is not.
//
// This enforces decision 2 -- "never emulation" -- and on macOS it is not theoretical. A
// `podman machine` on Apple Silicon registers a `rosetta` binfmt handler for x86-64 ELF plus
// qemu-user handlers for roughly 31 other architectures, so a foreign-arch image does not fail: it
// RUNS. Measured: `podman run --platform linux/amd64 ubuntu:24.04 uname -m` prints x86_64 on an
// arm64 machine.
//
// Two reasons that is worth a hard refusal rather than a warning:
//
//   1. It is exactly the guard that emulation defeats. An x86-64 agent baked into an arm64 image is
//      supposed to be a loud `exec format error` (podman exit 126). Under Rosetta it just works, so
//      the arch guard in scripts/build/agent.js -- which exists precisely to catch that -- reports
//      success for a build that ran emulated.
//   2. The attestation would not say so. A build that ran under emulation is attested identically to
//      one that did not, which makes the tier and the digest a promise the runner cannot keep.
//
// The check lives here rather than in machine configuration because configuration is not a control:
// whether Rosetta is enabled depends on how someone happened to create their VM, and a teammate's
// machine is not ours to configure. `podman machine set` cannot even turn Rosetta off -- only a fresh
// `init` can -- so relying on it would be relying on something we cannot enforce.

const WorkflowError = require('./../errors.js')

// podman reports Go arch names for images (`amd64`, `arm64`) and for the host. They already agree,
// so this normalizes only the aliases that show up from other tooling rather than inventing a map.
const ALIASES = {
  x86_64: 'amd64',
  aarch64: 'arm64',
  x64: 'amd64'
}

function normalize(arch) {
  if (!arch) return null
  const a = String(arch).trim().toLowerCase()
  return ALIASES[a] || a
}

// Which of `images` are not the runtime's architecture. `archOf` is injected so this stays a pure
// function and the test does not need a container runtime.
//
// An image whose arch cannot be determined is NOT treated as foreign: podman not answering is a
// different failure, reported elsewhere, and guessing here would turn an unrelated outage into a
// confusing architecture error.
function foreignImages(images, runtimeArch, archOf) {
  const runtime = normalize(runtimeArch)
  if (!runtime) return []
  const out = []
  for (const image of images) {
    const arch = normalize(archOf(image))
    if (arch && arch !== runtime) out.push({ image, arch, runtime })
  }
  return out
}

function explain(foreign) {
  const lines = ['refusing to run an image built for another architecture:']
  for (const f of foreign) {
    lines.push(`  ${f.image} is ${f.arch}, but the container runtime is ${f.runtime}`)
  }
  lines.push(
    '  This would run under emulation (Rosetta on macOS, or qemu-user), which this runner',
    '  refuses: an emulated build can be subtly wrong and the attestation would not say so.',
    `  Rebuild the image for ${foreign[0].runtime}, or point --image at one that matches.`
  )
  return lines.join('\n')
}

// Throws IMAGE_ARCH_MISMATCH when any image is foreign. Call before anything runs.
function assertNative(images, runtimeArch, archOf) {
  const foreign = foreignImages(images, runtimeArch, archOf)
  if (foreign.length) throw WorkflowError.IMAGE_ARCH_MISMATCH(explain(foreign))
  return foreign
}

module.exports = { foreignImages, assertNative, explain, normalize }
