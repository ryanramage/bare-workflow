'use strict'

// Render the canonical Seatbelt profile to etc/sandbox/build-v1.sb.
//
// HOW THIS DIFFERS FROM THE SECCOMP PROFILE, which is worth understanding before treating them the
// same. `etc/seccomp/build-v1.json` is the file podman is actually handed: one static document, used
// verbatim, its sha256 recorded in every attestation. A Seatbelt profile cannot be static -- it names
// the job's workspace and the host's toolchain paths, and those differ per job and per machine. So:
//
//   * The REAL profile is generated per job by the launcher, into the job's scratch directory, and
//     THAT rendering's sha256 is what goes into the attestation. It is the document that was actually
//     enforced.
//   * The file this script writes is the CANONICAL rendering -- the same generator run against fixed,
//     declared inputs. It exists to be reviewed and diffed, and the drift guard in test/sandbox.js
//     regenerates it to catch "someone changed the generator and did not regenerate". It is not the
//     file that runs.
//
// The probe in lib/isolation/darwin/probe.js also requires this file to exist, which is what keeps
// the tier honestly unavailable on a checkout where it has never been rendered.
//
//   bare scripts/build/sandbox.js           # render it
//   bare scripts/build/sandbox.js --check   # exit 1 if the committed rendering is stale

const fs = require('fs')
const path = require('path')

const sbpl = require('../../lib/isolation/darwin/sbpl.js')

const ROOT = path.join(__dirname, '..', '..')
const OUTPUT = path.join(ROOT, 'etc/sandbox/build-v1.sb')

// Fixed inputs, so the rendering is reproducible on any machine. Deliberately NOT this host's real
// paths: a profile whose committed form depended on whose laptop rendered it could not be diffed.
const CANONICAL = {
  workspace: '/w',
  toolchain: ['/CANONICAL/toolchain']
}

const argv = Bare.argv.slice(2)
const rendered = sbpl.serialize(sbpl.generate(CANONICAL))

if (argv.includes('--check')) {
  let committed = null
  try {
    committed = fs.readFileSync(OUTPUT, 'utf8')
  } catch {}
  if (committed === rendered) {
    console.log('up to date')
  } else {
    console.error('etc/sandbox/build-v1.sb is stale -- run: bare scripts/build/sandbox.js')
    Bare.exitCode = 1
  }
} else {
  fs.mkdirSync(path.dirname(OUTPUT), { recursive: true })
  fs.writeFileSync(OUTPUT, rendered)
  console.log(`wrote ${path.relative(ROOT, OUTPUT)}`)
}
