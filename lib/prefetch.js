'use strict'

// Lockfile-driven dependency prefetch.
//
// This is what makes `network: none` a real default rather than an aspiration. A build cannot run
// `npm install` with no network, so the runner fetches first -- on the HOST, before the sandbox
// exists -- and hands the result in as a read-only cache.
//
// Three properties, and the first two are the point:
//
//   1. IT RESOLVES NOTHING. Every URL and hash comes from the committed lockfile. There is no
//      registry metadata request, no version resolution, no dependency solving. If it is not in
//      package-lock.json it is not fetched, so what the sandbox sees is exactly what the repository
//      already recorded.
//   2. IT EXECUTES NO PACKAGE CODE. Nothing is unpacked and no lifecycle script runs; tarballs are
//      downloaded and verified, full stop. This is also why the install inside the sandbox uses
//      `--ignore-scripts` -- which is already the org's house style in actions/node-base.
//   3. EVERY TARBALL IS VERIFIED against the lockfile's `integrity` before it is kept. A registry
//      that serves different bytes than the lockfile recorded is a failure, not a surprise.
//
// The output is an npm cacache directory, which `npm ci --offline --cache <dir>` reads directly.

const fs = require('bare-fs')
const path = require('bare-path')
const crypto = require('bare-crypto')

const WorkflowError = require('./errors.js')

// Hosts a lockfile may legitimately point at. A lockfile is committed source, but it is also
// exactly where someone would redirect a fetch if they got a bad PR merged, so the runner keeps its
// own opinion about where bytes may come from.
const DEFAULT_ALLOWED_HOSTS = [
  'registry.npmjs.org',
  'npm.pkg.github.com',
  'codeload.github.com',
  'objects.githubusercontent.com'
]

// Read a lockfile and return the set of tarballs it pins.
//
// Supports lockfileVersion 2 and 3 (the `packages` map). v1's `dependencies` tree is handled too,
// because plenty of repositories still carry one.
// `includeDev` is off by default, and that default is load-bearing rather than lazy.
//
// A build job installs runtime dependencies; dev dependencies are for testing. The difference is not
// academic here -- hello-pear-bare carries `bare-build` as a devDependency, and `bare-build` pulls 13
// prebuilt Bare runtimes totalling ~1 GB. Prefetching that per run, to install something the
// toolchain image already provides, would make a first run unusable for no benefit.
//
// A workflow that genuinely needs dev dependencies (to run `npm test`, say) asks for `npm-dev`.
function planFromLockfile(lockfile, opts = {}) {
  const allowed = opts.allowedHosts || DEFAULT_ALLOWED_HOSTS
  const includeDev = opts.includeDev === true
  let doc
  try {
    doc = JSON.parse(lockfile)
  } catch (err) {
    throw WorkflowError.PREFETCH_INVALID(`package-lock.json is not valid JSON: ${err.message}`)
  }

  const wanted = new Map()
  const problems = []

  const consider = (name, node) => {
    if (!node || typeof node !== 'object') return
    if (node.link) return // a workspace symlink, not a tarball
    if (!includeDev && (node.dev === true || node.devOptional === true)) return
    const resolved = node.resolved
    const integrity = node.integrity
    if (!resolved) return // the root project itself, or a bundled dep
    if (!/^https?:\/\//.test(resolved)) {
      problems.push(`${name}: resolved is not an http(s) URL (${resolved})`)
      return
    }
    let host
    try {
      host = new URL(resolved).host
    } catch {
      problems.push(`${name}: resolved is not a parseable URL (${resolved})`)
      return
    }
    if (!allowed.includes(host)) {
      // Refuse rather than warn. A lockfile pointing somewhere unexpected is precisely the case
      // worth stopping on.
      problems.push(`${name}: host ${host} is not in the allowed set (${allowed.join(', ')})`)
      return
    }
    if (!integrity) {
      problems.push(
        `${name}: no integrity hash in the lockfile, so the download cannot be verified`
      )
      return
    }
    wanted.set(resolved, { name, url: resolved, integrity })
  }

  if (doc.packages && typeof doc.packages === 'object') {
    for (const key of Object.keys(doc.packages)) {
      if (key === '') continue // the root project
      consider(key, doc.packages[key])
    }
  }

  if (doc.dependencies && typeof doc.dependencies === 'object') {
    const walk = (deps, prefix) => {
      for (const name of Object.keys(deps)) {
        const node = deps[name]
        consider(prefix ? `${prefix}/${name}` : name, node)
        if (node && node.dependencies) {
          walk(node.dependencies, `${prefix ? prefix + '/' : ''}${name}`)
        }
      }
    }
    walk(doc.dependencies, '')
  }

  return { entries: [...wanted.values()], problems, lockfileVersion: doc.lockfileVersion || 1 }
}

// Verify bytes against a Subresource-Integrity string (`sha512-<base64>`), which is what npm writes.
function verifyIntegrity(buffer, integrity) {
  // A lockfile may list several alternatives; any match is enough.
  for (const candidate of String(integrity).trim().split(/\s+/)) {
    const dash = candidate.indexOf('-')
    if (dash === -1) continue
    const algo = candidate.slice(0, dash)
    const expected = candidate.slice(dash + 1)
    if (!['sha512', 'sha384', 'sha256', 'sha1'].includes(algo)) continue
    const actual = crypto.createHash(algo).update(buffer).digest('base64')
    if (actual === expected) return { ok: true, algo }
  }
  return { ok: false }
}

// Where npm looks for a cached tarball. cacache lays content out by hash so the layout is derivable
// from the integrity string alone -- no index rebuild needed for `--offline` reads of content.
function contentPath(cacheDir, integrity) {
  const candidate = String(integrity).trim().split(/\s+/)[0]
  const dash = candidate.indexOf('-')
  const algo = candidate.slice(0, dash)
  const hex = Buffer.from(candidate.slice(dash + 1), 'base64').toString('hex')
  return path.join(
    cacheDir,
    '_cacache',
    'content-v2',
    algo,
    hex.slice(0, 2),
    hex.slice(2, 4),
    hex.slice(4)
  )
}

// Fetch everything the plan names into `cacheDir`.
//
// `fetch` is injected so this is testable without a network, and so the real implementation can be
// swapped for one that talks through an allowlisting proxy later.
async function run(plan, cacheDir, opts = {}) {
  const fetchImpl = opts.fetch
  if (typeof fetchImpl !== 'function') {
    throw WorkflowError.PREFETCH_INVALID('prefetch requires a fetch implementation')
  }
  if (plan.problems.length && opts.strict !== false) {
    throw WorkflowError.PREFETCH_INVALID(
      'refusing to prefetch from an untrustworthy lockfile:\n  ' + plan.problems.join('\n  ')
    )
  }

  const results = { fetched: 0, cached: 0, bytes: 0, failures: [] }

  for (const entry of plan.entries) {
    const target = contentPath(cacheDir, entry.integrity)
    try {
      const stat = fs.statSync(target)
      if (stat.size > 0) {
        results.cached++
        continue
      }
    } catch {
      // not cached yet
    }

    let buffer
    try {
      buffer = await fetchImpl(entry.url)
    } catch (err) {
      results.failures.push(`${entry.name}: ${err.message}`)
      continue
    }

    const check = verifyIntegrity(buffer, entry.integrity)
    if (!check.ok) {
      // The registry served bytes that do not match what the repository recorded. That is a
      // supply-chain event, not a retryable error.
      results.failures.push(`${entry.name}: integrity mismatch against ${entry.integrity}`)
      continue
    }

    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, buffer)
    results.fetched++
    results.bytes += buffer.byteLength
  }

  if (results.failures.length && opts.strict !== false) {
    throw WorkflowError.PREFETCH_FAILED(
      `prefetch failed for ${results.failures.length} package(s):\n  ` +
        results.failures.join('\n  ')
    )
  }
  return results
}

module.exports = {
  planFromLockfile,
  verifyIntegrity,
  contentPath,
  run,
  DEFAULT_ALLOWED_HOSTS
}
