'use strict'

// Toolchain registry tests.
//
// The registry is what replaces GHA's `uses:`: a name in a workflow resolves to a curated image on
// disk, so no remote code is ever fetched into a runner. The tests worth having are about failing
// EARLY and CLEARLY -- a missing toolchain surfacing as `npm: command not found` thirty seconds into
// a sandboxed step is the exact experience this exists to prevent.

const test = require('brittle')
const toolchains = require('../lib/toolchains.js')
const { parse } = require('../lib/schema')

test('the default is the bare base image, not a toolchain', (t) => {
  // A workflow that needs npm has to say so; otherwise every sandbox ships tooling it does not use.
  t.is(toolchains.DEFAULT, 'bare')
  t.is(toolchains.resolve().name, 'bare')
  t.ok(toolchains.resolve().image.includes('bare-workflow-base'))
})

test('every registered toolchain carries an image and a build command', (t) => {
  for (const name of toolchains.names()) {
    const entry = toolchains.resolve(name)
    t.ok(entry.image && entry.image.includes(':'), `${name} names a tagged image`)
    t.ok(entry.build && entry.build.length > 0, `${name} says how to build it`)
    t.ok(entry.describe && entry.describe.length > 0, `${name} describes itself`)
  }
})

test('an unknown toolchain is refused with a suggestion', (t) => {
  t.exception(() => toolchains.resolve('nodejs'), /did you mean "node"/)
  t.exception(() => toolchains.resolve('rust'), /UNKNOWN_TOOLCHAIN/)
  try {
    toolchains.resolve('rust')
  } catch (err) {
    t.ok(err.message.includes('known: bare, node'), 'and lists what is available')
  }
})

test('a job overrides the workflow', (t) => {
  const workflow = { toolchain: 'bare' }
  t.is(toolchains.forJob({ toolchain: 'node' }, workflow).name, 'node', 'job wins')
  t.is(toolchains.forJob({ toolchain: null }, workflow).name, 'bare', 'falls back to the workflow')
  t.is(toolchains.forJob({ toolchain: null }, {}).name, 'bare', 'and then to the default')
})

test('a toolchain typo is caught at PARSE time', (t) => {
  // The whole point: this must not wait until a sandbox is running.
  t.exception(() => parse('version: 1\ntoolchain: nodejs\nsteps: [x]\n'), /did you mean "node"/)
  t.exception(
    () => parse('version: 1\njobs:\n  a:\n    toolchain: nope\n    steps: [x]\n'),
    /unknown toolchain/
  )
  t.exception(() => parse('version: 1\ntoolchain: 5\nsteps: [x]\n'), /must be a toolchain name/)
})

test('a valid toolchain survives parsing at both levels', (t) => {
  t.is(parse('version: 1\ntoolchain: node\nsteps: [x]\n').jobs.main.toolchain, 'node')
  const w = parse('version: 1\ntoolchain: bare\njobs:\n  a:\n    toolchain: node\n    steps: [x]\n')
  t.is(w.toolchain, 'bare')
  t.is(w.jobs.a.toolchain, 'node', 'the job override is preserved through the schema')
})

test('the examples declare the toolchains they need', (t) => {
  // examples/offline.yml runs npm, so it must not silently rely on a default that has no npm --
  // which is exactly the trap this replaced.
  const fs = require('bare-fs')
  const w = parse(fs.readFileSync('examples/offline.yml', 'utf8'), { filename: 'offline.yml' })
  t.is(w.jobs.test.toolchain, 'node', 'the offline example asks for node')
})
