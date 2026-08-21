'use strict'

// The toolchain registry: a name in a workflow, an image on disk.
//
// This is what replaces GHA's `uses:` entirely. A curated, versioned set resolving to a sandbox
// image -- mirroring what `actions/bare-base` and `actions/node-base` already are in practice --
// which means no remote code is ever fetched into a runner. It also deletes wrkflw's whole
// action-resolution surface along with a large attack surface.
//
// Every toolchain image layers on the SAME base, so the agent and the isolation posture are
// identical across all of them: a toolchain cannot weaken the sandbox, and there is one place to
// audit.

const WorkflowError = require('./errors.js')

// The default is `bare`, which is the base image: an OS, the agent, nothing else. That is
// deliberate -- a workflow that needs npm should have to say so, rather than every sandbox
// carrying a toolchain it does not use.
const DEFAULT = 'bare'

const TOOLCHAINS = {
  bare: {
    image: 'localhost/bare-workflow-base:dev',
    describe: 'the base sandbox: bash and the agent, no build tooling',
    build: 'bare scripts/build/agent.js'
  },
  node: {
    image: 'localhost/bare-workflow-node:dev',
    describe: 'node and npm',
    build: 'podman build -f etc/Containerfile.node -t localhost/bare-workflow-node:dev .'
  },
  'bare-build': {
    image: 'localhost/bare-workflow-bare-build:dev',
    describe: 'node, npm and bare-build with every prebuilt Bare runtime (~1.6 GB image)',
    build:
      'podman build -f etc/Containerfile.bare-build -t localhost/bare-workflow-bare-build:dev .'
  },
  pear: {
    image: 'localhost/bare-workflow-pear:dev',
    describe: 'node, npm and pear-build for assembling by-arch/ deployment folders',
    build: 'podman build -f etc/Containerfile.pear -t localhost/bare-workflow-pear:dev .'
  }
}

function names() {
  return Object.keys(TOOLCHAINS)
}

function resolve(name) {
  const key = name || DEFAULT
  const entry = TOOLCHAINS[key]
  if (!entry) {
    const near = closest(key, names())
    throw WorkflowError.UNKNOWN_TOOLCHAIN(
      `unknown toolchain ${JSON.stringify(key)}${near ? `; did you mean ${JSON.stringify(near)}?` : ''}; ` +
        `known: ${names().join(', ')}`
    )
  }
  return { name: key, ...entry }
}

// Which toolchain a task actually runs under. Job overrides workflow; an explicit --image on the
// command line overrides both, because that is the escape hatch for trying an image that has no
// registry entry yet.
function forJob(job, workflow) {
  return resolve(job.toolchain || workflow.toolchain || DEFAULT)
}

function closest(word, candidates) {
  let best = null
  let score = Infinity
  for (const c of candidates) {
    const d = distance(word, c)
    if (d < score) {
      score = d
      best = c
    }
  }
  return score <= Math.max(2, Math.floor(word.length / 3)) ? best : null
}

function distance(a, b) {
  const rows = [[...Array(b.length + 1).keys()]]
  for (let i = 1; i <= a.length; i++) rows.push([i])
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      rows[i][j] = Math.min(
        rows[i - 1][j] + 1,
        rows[i][j - 1] + 1,
        rows[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      )
    }
  }
  return rows[a.length][b.length]
}

module.exports = { TOOLCHAINS, DEFAULT, names, resolve, forJob }
