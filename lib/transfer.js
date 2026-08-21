'use strict'

// Validating tar in and out.
//
// This is the only way data crosses the sandbox boundary, so it is the only place a malicious
// archive can hurt us. Every entry is checked before it touches the filesystem.
//
// Deliberately NOT `podman cp`: its man page notes it resolves symlinks, and its host-side
// extraction is not something to put in the trust path. We produce the tar, we parse the tar, and
// we decide entry by entry what is allowed to exist.
//
// The threat is not hypothetical. An archive coming OUT of a sandbox was written by the workload --
// which is untrusted by construction -- so it can contain a symlink to /etc/passwd, a path full of
// `..`, a 10 GB sparse file, a million entries, or a name that only collides on a
// case-insensitive filesystem. Each of those is a test in test/transfer.js.

const tar = require('tar-stream')
const fs = require('bare-fs')
const path = require('bare-path')

const WorkflowError = require('./errors.js')

const DEFAULTS = {
  maxEntries: 100000,
  maxBytes: 2 * 1024 * 1024 * 1024, // whole archive
  maxFileBytes: 512 * 1024 * 1024, // any single member
  maxPathLength: 1024,
  maxDepth: 32,
  // Only these two. Every other type is a way to reference something outside the archive.
  allowedTypes: ['file', 'directory']
}

// Windows reserves these names regardless of extension. Rejecting them now costs nothing and saves
// a confusing failure the first time an artifact is extracted on a Windows peer.
const WINDOWS_RESERVED = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  'com1',
  'com2',
  'com3',
  'com4',
  'com5',
  'com6',
  'com7',
  'com8',
  'com9',
  'lpt1',
  'lpt2',
  'lpt3',
  'lpt4',
  'lpt5',
  'lpt6',
  'lpt7',
  'lpt8',
  'lpt9'
])

// Validate one entry name. Returns the normalized relative path, or throws.
function checkName(name, opts) {
  if (typeof name !== 'string' || name.length === 0) {
    throw WorkflowError.TRANSFER_REJECTED('archive entry has no name')
  }
  if (name.length > opts.maxPathLength) {
    throw WorkflowError.TRANSFER_REJECTED(
      `archive entry name exceeds ${opts.maxPathLength} characters`
    )
  }
  // NUL and newline in a filename are almost always an attempt to confuse something downstream
  // that treats output as line-oriented.
  if (name.includes('\0') || name.includes('\n') || name.includes('\r')) {
    throw WorkflowError.TRANSFER_REJECTED(
      `archive entry name contains a control character: ${JSON.stringify(name)}`
    )
  }
  if (name.startsWith('/') || /^[A-Za-z]:/.test(name)) {
    throw WorkflowError.TRANSFER_REJECTED(`archive entry name is absolute: ${JSON.stringify(name)}`)
  }

  const parts = name.split('/').filter((p) => p !== '' && p !== '.')
  if (parts.length === 0) {
    throw WorkflowError.TRANSFER_REJECTED(
      `archive entry name is empty after normalization: ${JSON.stringify(name)}`
    )
  }
  if (parts.length > opts.maxDepth) {
    throw WorkflowError.TRANSFER_REJECTED(
      `archive entry is nested deeper than ${opts.maxDepth}: ${JSON.stringify(name)}`
    )
  }
  for (const part of parts) {
    // A single `..` anywhere is enough to escape, so reject the component rather than trying to
    // resolve the path and check afterwards.
    if (part === '..') {
      throw WorkflowError.TRANSFER_REJECTED(
        `archive entry name escapes its root: ${JSON.stringify(name)}`
      )
    }
    const stem = part.split('.')[0].toLowerCase()
    if (WINDOWS_RESERVED.has(stem)) {
      throw WorkflowError.TRANSFER_REJECTED(
        `archive entry uses a Windows-reserved name (${part}): ${JSON.stringify(name)}`
      )
    }
  }
  return parts.join('/')
}

// Extract a tar stream into `dest`, which must be a fresh empty directory.
//
// Returns { files, bytes, entries }. Throws on the first violation: a partially-extracted malicious
// archive is not a state we want to reason about, and the caller is expected to discard `dest`.
function extract(stream, dest, opts = {}) {
  const o = { ...DEFAULTS, ...opts }
  const root = path.resolve(dest)

  return new Promise((resolve, reject) => {
    let files = 0
    let dirs = 0
    let bytes = 0
    let entries = 0
    let failed = null
    // Case-insensitive collision detection. Free here, and it saves an artifact built on Linux
    // from silently losing files when it is extracted on a mac or Windows peer.
    const lowered = new Map()

    const parser = tar.extract()

    parser.on('entry', (header, source, next) => {
      if (failed) {
        source.resume()
        return next()
      }
      try {
        if (++entries > o.maxEntries) {
          throw WorkflowError.TRANSFER_REJECTED(`archive has more than ${o.maxEntries} entries`)
        }
        if (!o.allowedTypes.includes(header.type)) {
          // symlink, hardlink, fifo, char/block device -- each is a way to point outside the
          // archive, and none is needed to move a build artifact.
          throw WorkflowError.TRANSFER_REJECTED(
            `archive entry ${JSON.stringify(header.name)} has forbidden type ${JSON.stringify(header.type)}`
          )
        }

        const rel = checkName(header.name, o)
        const lower = rel.toLowerCase()
        if (lowered.has(lower) && lowered.get(lower) !== rel) {
          throw WorkflowError.TRANSFER_REJECTED(
            `archive entries collide case-insensitively: ${JSON.stringify(lowered.get(lower))} and ${JSON.stringify(rel)}`
          )
        }
        lowered.set(lower, rel)

        const size = header.size || 0
        if (size > o.maxFileBytes) {
          throw WorkflowError.TRANSFER_REJECTED(
            `archive entry ${JSON.stringify(rel)} is larger than ${o.maxFileBytes} bytes`
          )
        }
        if (bytes + size > o.maxBytes) {
          throw WorkflowError.TRANSFER_REJECTED(`archive exceeds ${o.maxBytes} bytes in total`)
        }

        const target = path.join(root, rel)

        if (header.type === 'directory') {
          fs.mkdirSync(target, { recursive: true })
          dirs++
          source.resume()
          return source.on('end', next)
        }

        fs.mkdirSync(path.dirname(target), { recursive: true })

        // Modes are masked, never taken from the archive: a setuid bit in an artifact is not
        // something we want to reproduce on the host.
        const chunks = []
        let written = 0
        source.on('data', (chunk) => {
          written += chunk.byteLength
          // Guard the declared-vs-actual mismatch too: a header can lie about its size.
          if (written > o.maxFileBytes || bytes + written > o.maxBytes) {
            failed =
              failed ||
              WorkflowError.TRANSFER_REJECTED(
                `archive entry ${JSON.stringify(rel)} exceeded its declared size`
              )
            return
          }
          chunks.push(chunk)
        })
        source.on('end', () => {
          if (failed) return next()
          try {
            fs.writeFileSync(target, Buffer.concat(chunks), { mode: 0o644 })
            files++
            bytes += written
          } catch (err) {
            failed = failed || err
          }
          next()
        })
        source.on('error', (err) => {
          failed = failed || err
          next()
        })
      } catch (err) {
        failed = err
        source.resume()
        source.on('end', next)
      }
    })

    parser.on('error', (err) => reject(failed || err))
    parser.on('finish', () => (failed ? reject(failed) : resolve({ files, dirs, bytes, entries })))

    stream.on('error', (err) => reject(err))
    stream.pipe(parser)
  })
}

// Pack a directory tree into a tar stream, applying the same rules on the way out.
//
// Symlinks are SKIPPED rather than followed. Following them would let a build smuggle out anything
// the sandbox could read by planting a link; skipping them means an artifact contains only real
// bytes the build actually produced.
function pack(dir, opts = {}) {
  const o = { ...DEFAULTS, ...opts }
  const root = path.resolve(dir)
  const packer = tar.pack()
  const match = opts.match || (() => true)

  const skipped = []
  let files = 0
  let bytes = 0

  function walk(current, prefix) {
    let names
    try {
      names = fs.readdirSync(current)
    } catch {
      return
    }
    names.sort() // deterministic archives; two runs of the same tree produce the same bytes

    for (const name of names) {
      const abs = path.join(current, name)
      const rel = prefix ? prefix + '/' + name : name

      let stat
      try {
        stat = fs.lstatSync(abs)
      } catch {
        continue
      }

      if (stat.isSymbolicLink()) {
        skipped.push({ path: rel, reason: 'symlink' })
        continue
      }
      if (stat.isDirectory()) {
        walk(abs, rel)
        continue
      }
      if (!stat.isFile()) {
        skipped.push({ path: rel, reason: 'not a regular file' })
        continue
      }
      if (!match(rel)) continue

      if (stat.size > o.maxFileBytes) {
        skipped.push({ path: rel, reason: `larger than ${o.maxFileBytes} bytes` })
        continue
      }
      if (bytes + stat.size > o.maxBytes) {
        throw WorkflowError.TRANSFER_REJECTED(
          `archive would exceed ${o.maxBytes} bytes at ${JSON.stringify(rel)}`
        )
      }

      packer.entry(
        { name: rel, size: stat.size, mode: stat.mode & 0o755, mtime: new Date(0) },
        fs.readFileSync(abs)
      )
      files++
      bytes += stat.size
    }
  }

  try {
    walk(root, '')
    packer.finalize()
  } catch (err) {
    packer.destroy(err)
  }

  packer.stats = {
    get files() {
      return files
    },
    get bytes() {
      return bytes
    },
    skipped
  }
  return packer
}

// A destination must be fresh and empty. Extracting over existing content lets an archive replace
// files that were already there, which is a different (and worse) operation than "unpack this".
function freshDir(dest) {
  const resolved = path.resolve(dest)
  let existing = null
  try {
    existing = fs.readdirSync(resolved)
  } catch {
    fs.mkdirSync(resolved, { recursive: true, mode: 0o700 })
    return resolved
  }
  if (existing.length > 0) {
    throw WorkflowError.TRANSFER_REJECTED(`extraction target is not empty: ${resolved}`)
  }
  return resolved
}

module.exports = { extract, pack, checkName, freshDir, DEFAULTS, WINDOWS_RESERVED }
