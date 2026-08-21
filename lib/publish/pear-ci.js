'use strict'

// The `pear-ci` publish driver.
//
// `pear stage` itself cannot be used here, and the reason is structural rather than incidental:
// `pear/subsystems/sidecar/ops/stage.js` calls `sidecar.ready()` and
// `sidecar.getCorestore({ writable: true })`, so it needs a long-lived sidecar owning a Corestore
// and a Hyperswarm. `pear-ci` is the org's own answer to exactly that -- a stateless stage that
// takes a primary key, derives the drive, mirrors a directory in, replicates, and writes back a
// snapshot of core lengths. Nothing to keep running between builds.
//
// Two behaviours of the underlying library are worth knowing before reading the code, because both
// shaped it:
//
//   * `stage()` WAITS FOR A PEER. It polls until `remoteContiguousLength` catches up to the local
//     length on both cores, which never happens if nothing else is online. Unwrapped, publishing
//     into an unseeded network hangs forever with no output. So every call is raced against a
//     deadline and a timeout is reported as the diagnosis it actually is: nobody is seeding.
//   * THE SNAPSHOT IS DURABLE STATE, and an input as much as an output. Lose it and the next run
//     re-uploads everything; fork it and two runners fight over one drive. It lives in the state
//     directory, and its length before and after is recorded so a publish is auditable.

const fs = require('fs')
const path = require('path')

const WorkflowError = require('../errors.js')

const DEFAULT_TIMEOUT_MS = 120000

// `require('pear-ci')` does not work on Bare, and it is worth being precise about why rather than
// working around it blindly. Every one of pear-ci's own dependencies -- corestore, hyperdrive,
// hyperswarm, mirror-drive, ready-resource, pear-link -- ships an `imports` map, so all of them load
// natively. pear-ci itself ships none while requiring `fs` and `path`, so those two specifiers have
// nowhere to resolve to. It is a six-line omission in its package.json, not a portability problem.
//
// So the map is supplied at the load site instead, using bare-module's documented `imports` option.
// Children inherit it, which is exactly the semantics a package.json `imports` map would have given.
// When upstream adds the map this collapses back to a plain `require`, with no other change here.
const PEAR_CI_IMPORTS = {
  fs: { bare: 'bare-fs', default: 'fs' },
  path: { bare: 'bare-path', default: 'path' }
}

let cached = null

function loadPearCI() {
  if (cached) return cached
  try {
    const Module = require('bare-module')
    const from = new URL('file://' + __dirname + '/')
    cached = Module.load(Module.resolve('pear-ci', from), { imports: PEAR_CI_IMPORTS }).exports
    return cached
  } catch (err) {
    throw WorkflowError.PUBLISH_REFUSED(
      'the pear-ci driver needs the `pear-ci` package: npm install pear-ci\n' + `  (${err.message})`
    )
  }
}

// A primary key is 32 bytes. Anything else is a configuration mistake worth naming precisely,
// because the failure it otherwise causes -- a drive under a different identity -- looks like a
// working publish to a completely wrong address.
function parsePrimaryKey(hex, where) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw WorkflowError.PUBLISH_REFUSED(
      `${where}: primaryKey must be exactly 64 hex characters (32 bytes), got ` +
        `${hex.length} character${hex.length === 1 ? '' : 's'}\n` +
        '  a wrong-length key derives a DIFFERENT drive, which would publish successfully to an ' +
        'address nobody is listening on'
    )
  }
  return Buffer.from(hex, 'hex')
}

function readSnapshot(file) {
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8'))
    return Array.isArray(doc) ? doc : []
  } catch {
    return []
  }
}

// Summarise a snapshot without leaking anything: core ids are public keys, and the lengths are the
// point -- "did this publish move the drive forward, and by how much".
function summarize(entries) {
  return {
    cores: entries.length,
    length: entries.reduce((n, e) => n + (e.length || 0), 0)
  }
}

// `opts`:
//   primaryKey  hex, from runner config -- never from the workflow
//   name        drive namespace
//   dir         the directory to stage (an extracted artifact)
//   snapshot    path to the durable snapshot JSON
//   storage     throwaway Corestore storage
//   dryRun      compute the diff, write nothing
//   bootstrap   Hyperswarm bootstrap, for testing against @hyperswarm/testnet
async function publish(opts) {
  const PearCI = loadPearCI()

  const key = parsePrimaryKey(opts.primaryKey, 'publish key')
  const snapshot = path.resolve(opts.snapshot)
  const before = summarize(readSnapshot(snapshot))

  fs.mkdirSync(path.dirname(snapshot), { recursive: true })
  fs.mkdirSync(opts.storage, { recursive: true })

  const ci = new PearCI(key, opts.name, snapshot, opts.dir, opts.storage, !!opts.dryRun, {
    bootstrap: opts.bootstrap
  })

  const diffs = []
  ci.on('diff', (diff) => {
    if (diffs.length < 1000) diffs.push({ op: diff.op, key: diff.key })
    if (opts.onDiff) opts.onDiff(diff)
  })
  if (opts.onSyncing) ci.on('syncing', opts.onSyncing)

  const timeoutMs = opts.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : opts.timeoutMs
  let timer = null
  let link = null

  try {
    await race(
      (async () => {
        await ci.ready()
        // Available only once the drive is open, and the reason this is captured mid-flight: on a
        // timeout we still want to report WHICH drive we failed to publish to.
        link = 'pear://' + ci.drive.core.id
        if (opts.onReady) opts.onReady({ link })
        await ci.stage()
      })(),
      timeoutMs,
      () => {
        const stage = link ? 'replicating to' : 'connecting to'
        return WorkflowError.PUBLISH_FAILED(
          `timed out after ${Math.round(timeoutMs / 1000)}s ${stage} the network` +
            (link ? ` for ${link}` : '') +
            '\n  Staging is not finished until another peer has replicated the new blocks, so this ' +
            'usually means\n  nothing is seeding this drive. `pear seed` must be running somewhere ' +
            'permanent for a publish\n  to complete -- it is infrastructure, not a build step.'
        )
      },
      (t) => {
        timer = t
      }
    )
  } finally {
    if (timer) clearTimeout(timer)
    // ready-resource close is idempotent, and on the timeout path the instance is still holding a
    // swarm we very much want to let go of.
    try {
      await ci.close()
    } catch {}
  }

  const after = summarize(readSnapshot(snapshot))

  return {
    driver: 'pear-ci',
    link,
    name: opts.name,
    dryRun: !!opts.dryRun,
    // The record answers "what is at this link" without needing the logs: how many entries changed,
    // and whether the drive actually moved.
    changed: diffs.length,
    diffs: diffs.slice(0, 50),
    snapshot: { path: snapshot, before, after }
  }
}

function race(promise, ms, makeError, keepTimer) {
  if (!(ms > 0)) return promise
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(makeError()), ms)
    keepTimer(timer)
    promise.then(
      (v) => {
        clearTimeout(timer)
        resolve(v)
      },
      (err) => {
        clearTimeout(timer)
        reject(err)
      }
    )
  })
}

module.exports = { publish, parsePrimaryKey, DEFAULT_TIMEOUT_MS }
