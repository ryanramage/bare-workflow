'use strict'

// Runner-side configuration: the only place a secret exists.
//
// A workflow file names a key (`key: hello-pear`); this resolves that name. The split is the whole
// point. A workflow is reviewable, shareable, and often untrusted -- it is the thing a contributor
// sends you. Configuration is none of those: it lives on the machine, outside the repository, and
// nothing in a workflow can read it or enumerate it. So a build can ask to publish under an
// identity the runner already trusts, and can never learn what that identity is.
//
// Two properties are enforced rather than documented:
//
//   * FILE PERMISSIONS. A config holding a private key that is readable by other local users is
//     not a working setup with a caveat, it is a leaked key. Refuse and say so.
//   * NOTHING IS RETURNED BY ACCIDENT. `secret()` takes an explicit name and field. There is no
//     "give me the config" accessor, because the moment one exists something starts logging it.

const fs = require('fs')
const path = require('path')
const env = require('bare-env')
const os = require('bare-os')

const WorkflowError = require('./errors.js')

function defaultPath() {
  const xdg = env.XDG_CONFIG_HOME
  const home = env.HOME || os.homedir()
  const base = xdg && xdg.startsWith('/') ? xdg : path.join(home, '.config')
  return path.join(base, 'bare-workflow', 'config.json')
}

class Config {
  constructor(file, doc) {
    this.file = file
    // NON-ENUMERABLE, deliberately. A plain field here means `JSON.stringify(config)` prints every
    // private key the file holds -- and something eventually logs an object. The secret must be
    // reachable only through the explicit accessor below, so that reading it is always a visible
    // decision in the code rather than a side effect of debugging.
    Object.defineProperty(this, '_doc', { value: doc, enumerable: false, writable: false })
  }

  // Belt and braces: even if `_doc` were reachable, this is what JSON.stringify uses.
  toJSON() {
    return { file: this.file, keys: this.names() }
  }

  // Look up one field of one named entry. Missing is an error with the fix in it, because the
  // alternative -- undefined flowing into a driver -- surfaces as a confusing failure much later.
  secret(name, field) {
    const entry = this._doc.keys && this._doc.keys[name]
    if (!entry) {
      const known = Object.keys(this._doc.keys || {})
      throw WorkflowError.CONFIG_MISSING(
        `no key named ${JSON.stringify(name)} in ${this.file}\n` +
          (known.length
            ? `  configured: ${known.join(', ')}`
            : '  the file configures no keys at all') +
          `\n  add it as: { "keys": { ${JSON.stringify(name)}: { "primaryKey": "<64 hex chars>" } } }`
      )
    }
    const value = entry[field]
    if (typeof value !== 'string' || value.length === 0) {
      throw WorkflowError.CONFIG_MISSING(
        `key ${JSON.stringify(name)} in ${this.file} has no ${JSON.stringify(field)}`
      )
    }
    return value
  }

  has(name) {
    return !!(this._doc.keys && this._doc.keys[name])
  }

  // Safe to log: names only, never values.
  names() {
    return Object.keys(this._doc.keys || {}).sort()
  }
}

// `required: false` returns null when the file is absent, so a dry run works on a machine that has
// never been configured -- which is the common case and should not need a key.
function load(file, opts = {}) {
  const resolved = path.resolve(file || defaultPath())

  let stat
  try {
    stat = fs.statSync(resolved)
  } catch {
    if (opts.required === false) return null
    throw WorkflowError.CONFIG_MISSING(
      `no runner config at ${resolved}\n` +
        '  create it with mode 0600 and a "keys" mapping, or pass --config <file>'
    )
  }

  // 0o077: any permission at all for group or other. Not a style preference -- this file holds a
  // private key, and on a shared machine a readable one is already compromised.
  const loose = stat.mode & 0o077
  if (loose) {
    throw WorkflowError.CONFIG_INSECURE(
      `${resolved} is readable by other users (mode ${(stat.mode & 0o777).toString(8)})\n` +
        `  it holds private keys; fix it with: chmod 600 ${resolved}`
    )
  }

  let doc
  try {
    doc = JSON.parse(fs.readFileSync(resolved, 'utf8'))
  } catch (err) {
    throw WorkflowError.CONFIG_INVALID(`${resolved} is not valid JSON: ${err.message}`)
  }
  if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) {
    throw WorkflowError.CONFIG_INVALID(`${resolved} must contain a JSON object`)
  }
  if (doc.keys !== undefined && (typeof doc.keys !== 'object' || Array.isArray(doc.keys))) {
    throw WorkflowError.CONFIG_INVALID(`${resolved}: "keys" must be a mapping of name to entry`)
  }

  return new Config(resolved, doc)
}

module.exports = { load, defaultPath, Config }
