'use strict'

// Artifact store, built against a DRIVE rather than a path.
//
// This is the single highest-leverage decision for making the farm cheap. `localdrive` and
// `hyperdrive` expose the same surface -- put/get/entry/del/list/mirror/createReadStream --
// so v1 passes a Localdrive and the farm later passes a Hyperdrive, at which point returning an
// artifact from a peer is `drive.mirror()` and `pear stage`/`seed`/`dump` already speak the format
// natively. Nothing in this file knows which one it has.
//
// Artifacts are keyed `/<runId>/<name>/<relative path>`. The run id is in the key so two runs of
// the same workflow cannot overwrite each other's outputs, which matters the moment anything is
// retained or replicated.

const fs = require('bare-fs')
const path = require('bare-path')

const WorkflowError = require('./../errors.js')

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

class Store {
  constructor({ drive, runId }) {
    if (!drive) throw WorkflowError.INVALID_SPEC('store requires a drive')
    if (!runId) throw WorkflowError.INVALID_SPEC('store requires a runId')
    this.drive = drive
    this.runId = String(runId)
  }

  // Artifact names end up in keys and, later, in URLs and filenames on other people's machines.
  // Validate rather than sanitize: silently rewriting a name makes it hard to find again.
  _key(name, rel) {
    if (!NAME.test(name)) {
      throw WorkflowError.INVALID_SPEC(
        `artifact name ${JSON.stringify(name)} must match ${NAME} (letters, digits, dot, dash, underscore)`
      )
    }
    const suffix = rel ? '/' + rel.split('/').filter(Boolean).join('/') : ''
    return `/${this.runId}/${name}${suffix}`
  }

  // Ingest a local directory tree that was already extracted from a sandbox -- so it has been
  // through lib/transfer.js validation and contains regular files only.
  async put(name, dir, opts = {}) {
    const root = path.resolve(dir)
    const files = []
    let bytes = 0

    const walk = (current, prefix) => {
      let names
      try {
        names = fs.readdirSync(current)
      } catch {
        return
      }
      names.sort()
      for (const entry of names) {
        const abs = path.join(current, entry)
        const rel = prefix ? prefix + '/' + entry : entry
        let stat
        try {
          stat = fs.lstatSync(abs)
        } catch {
          continue
        }
        // Symlinks were already excluded upstream; skip defensively rather than trusting that.
        if (stat.isSymbolicLink()) continue
        if (stat.isDirectory()) {
          walk(abs, rel)
          continue
        }
        if (!stat.isFile()) continue
        files.push({ abs, rel, size: stat.size })
        bytes += stat.size
      }
    }
    walk(root, '')

    if (files.length === 0 && opts.ifNoFilesFound === 'error') {
      throw WorkflowError.ARTIFACT_EMPTY(`artifact ${JSON.stringify(name)} matched no files`)
    }

    for (const file of files) {
      await this.drive.put(this._key(name, file.rel), fs.readFileSync(file.abs))
    }
    return { name, files: files.length, bytes }
  }

  // Materialize an artifact into a local directory, for handing to a later task.
  async get(name, dir) {
    const prefix = this._key(name)
    const dest = path.resolve(dir)
    fs.mkdirSync(dest, { recursive: true })

    let files = 0
    let bytes = 0
    for await (const entry of this.drive.list(prefix)) {
      const rel = entry.key.slice(prefix.length).replace(/^\//, '')
      if (!rel) continue
      const target = path.join(dest, rel)
      fs.mkdirSync(path.dirname(target), { recursive: true })
      const buf = await this.drive.get(entry.key)
      fs.writeFileSync(target, buf, { mode: 0o644 })
      files++
      bytes += buf.byteLength
    }
    if (files === 0) {
      throw WorkflowError.ARTIFACT_MISSING(
        `no artifact named ${JSON.stringify(name)} in run ${this.runId}`
      )
    }
    return { name, files, bytes, dir: dest }
  }

  // What this run has produced so far.
  async list() {
    const prefix = `/${this.runId}/`
    const byName = new Map()
    for await (const entry of this.drive.list(prefix)) {
      const rest = entry.key.slice(prefix.length)
      const name = rest.split('/')[0]
      if (!name) continue
      const current = byName.get(name) || { name, files: 0, bytes: 0 }
      current.files++
      current.bytes += entry.value && entry.value.blob ? entry.value.blob.byteLength || 0 : 0
      byName.set(name, current)
    }
    return [...byName.values()].sort((a, b) => (a.name < b.name ? -1 : 1))
  }

  async has(name) {
    const prefix = this._key(name)
    for await (const entry of this.drive.list(prefix)) {
      if (entry) return true
    }
    return false
  }
}

function create(opts) {
  return new Store(opts)
}

// Convenience for v1: a Localdrive under a state directory. The farm swaps this for a Hyperdrive
// without the Store noticing.
function localStore({ root, runId }) {
  const Localdrive = require('localdrive')
  return new Store({ drive: new Localdrive(path.resolve(root)), runId })
}

module.exports = { Store, create, localStore, NAME }
