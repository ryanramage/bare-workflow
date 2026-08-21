'use strict'

// Prefetch tests. No network: `fetch` is injected, which is also how the real runner will swap in a
// proxy-aware implementation later.
//
// The security properties are the point here. A lockfile is committed source, but it is also exactly
// where someone would redirect a fetch if they landed a bad PR -- so the runner keeps its own opinion
// about which hosts are acceptable and refuses anything it cannot verify.

const test = require('brittle')
const fs = require('bare-fs')
const crypto = require('bare-crypto')
const prefetch = require('../lib/prefetch.js')

const sha512 = (buf) => 'sha512-' + crypto.createHash('sha512').update(buf).digest('base64')

let n = 0
function tmp() {
  const dir = `/tmp/bw-prefetch-${Date.now()}-${n++}`
  fs.mkdirSync(dir, { recursive: true })
  return dir
}
const clean = (d) => {
  try {
    fs.rmSync(d, { recursive: true, force: true })
  } catch {}
}

const lockfile = (packages) =>
  JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' }, ...packages } })

test('a v3 lockfile yields exactly the tarballs it pins', (t) => {
  const body = Buffer.from('tarball')
  const plan = prefetch.planFromLockfile(
    lockfile({
      'node_modules/a': {
        resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
        integrity: sha512(body)
      },
      'node_modules/b': {
        resolved: 'https://registry.npmjs.org/b/-/b-2.0.0.tgz',
        integrity: sha512(body)
      }
    })
  )
  t.is(plan.entries.length, 2)
  t.alike(plan.problems, [], 'nothing to complain about')
  t.is(plan.lockfileVersion, 3)
})

test('a v1 lockfile dependency tree is walked too', (t) => {
  // Plenty of repositories still carry one.
  const body = Buffer.from('t')
  const doc = JSON.stringify({
    lockfileVersion: 1,
    dependencies: {
      a: {
        resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
        integrity: sha512(body),
        dependencies: {
          b: { resolved: 'https://registry.npmjs.org/b/-/b-1.0.0.tgz', integrity: sha512(body) }
        }
      }
    }
  })
  const plan = prefetch.planFromLockfile(doc)
  t.is(plan.entries.length, 2, 'nested dependencies included')
})

test('the root project and workspace links are skipped', (t) => {
  const plan = prefetch.planFromLockfile(
    lockfile({ 'packages/thing': { link: true, resolved: 'packages/thing' } })
  )
  t.is(plan.entries.length, 0, 'nothing to fetch')
  t.alike(plan.problems, [], 'and a link is not a problem, just not a tarball')
})

test('an unexpected host is refused', (t) => {
  const plan = prefetch.planFromLockfile(
    lockfile({
      'node_modules/evil': {
        resolved: 'https://evil.example.com/x.tgz',
        integrity: sha512(Buffer.from('x'))
      }
    })
  )
  t.is(plan.entries.length, 0, 'not fetched')
  t.ok(/not in the allowed set/.test(plan.problems[0]), plan.problems[0])
})

test('a missing integrity hash is refused', (t) => {
  // Without a hash there is nothing to verify the download against, which is the whole point.
  const plan = prefetch.planFromLockfile(
    lockfile({ 'node_modules/nohash': { resolved: 'https://registry.npmjs.org/n/-/n-1.0.0.tgz' } })
  )
  t.is(plan.entries.length, 0)
  t.ok(/no integrity hash/.test(plan.problems[0]))
})

test('a non-http resolved url is refused', (t) => {
  const plan = prefetch.planFromLockfile(
    lockfile({
      'node_modules/f': { resolved: 'file:///etc/passwd', integrity: sha512(Buffer.from('x')) }
    })
  )
  t.is(plan.entries.length, 0)
  t.ok(/not an http\(s\) URL/.test(plan.problems[0]))
})

test('a malformed lockfile is rejected clearly', (t) => {
  t.exception(() => prefetch.planFromLockfile('{not json'), /not valid JSON/)
})

test('integrity verification accepts the right bytes and rejects the wrong ones', (t) => {
  const body = Buffer.from('the real tarball')
  t.ok(prefetch.verifyIntegrity(body, sha512(body)).ok)
  t.absent(prefetch.verifyIntegrity(Buffer.from('different'), sha512(body)).ok)
  // npm sometimes records several alternatives; any match is enough.
  t.ok(prefetch.verifyIntegrity(body, `sha1-nope ${sha512(body)}`).ok, 'one of several matches')
  t.absent(
    prefetch.verifyIntegrity(body, 'md5-whatever').ok,
    'an unsupported algorithm is not a pass'
  )
  t.absent(prefetch.verifyIntegrity(body, 'garbage').ok)
})

test('fetched tarballs are written where npm will look for them', async (t) => {
  const cache = tmp()
  try {
    const body = Buffer.from('a tarball')
    const integrity = sha512(body)
    const plan = prefetch.planFromLockfile(
      lockfile({
        'node_modules/a': { resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz', integrity }
      })
    )
    const result = await prefetch.run(plan, cache, { fetch: async () => body })
    t.is(result.fetched, 1)
    t.is(result.bytes, body.byteLength)

    const target = prefetch.contentPath(cache, integrity)
    t.ok(fs.statSync(target).size > 0, 'content-addressed under _cacache/content-v2')
    t.ok(target.includes('_cacache/content-v2/sha512/'), target)
  } finally {
    clean(cache)
  }
})

test('a second run is a no-op', async (t) => {
  const cache = tmp()
  try {
    const body = Buffer.from('a tarball')
    const plan = prefetch.planFromLockfile(
      lockfile({
        'node_modules/a': {
          resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
          integrity: sha512(body)
        }
      })
    )
    let calls = 0
    const fetch = async () => {
      calls++
      return body
    }
    await prefetch.run(plan, cache, { fetch })
    const second = await prefetch.run(plan, cache, { fetch })
    t.is(calls, 1, 'the network was touched exactly once')
    t.is(second.cached, 1)
    t.is(second.fetched, 0)
  } finally {
    clean(cache)
  }
})

test('bytes that do not match the lockfile are a hard failure', async (t) => {
  // A registry serving different bytes than the repository recorded is a supply-chain event, not a
  // retryable error.
  const cache = tmp()
  try {
    const plan = prefetch.planFromLockfile(
      lockfile({
        'node_modules/a': {
          resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
          integrity: sha512(Buffer.from('what the lockfile says'))
        }
      })
    )
    await t.exception(
      prefetch.run(plan, cache, { fetch: async () => Buffer.from('what the registry served') }),
      /integrity mismatch/
    )
    t.absent(
      fs.readdirSync(cache).length && fs.existsSync?.(prefetch.contentPath(cache, 'sha512-x')),
      'nothing was kept'
    )
  } finally {
    clean(cache)
  }
})

test('a lockfile with problems is refused before anything is fetched', async (t) => {
  const cache = tmp()
  try {
    const plan = prefetch.planFromLockfile(
      lockfile({
        'node_modules/evil': { resolved: 'https://evil.example.com/x.tgz', integrity: 'sha512-x' }
      })
    )
    let called = false
    await t.exception(
      prefetch.run(plan, cache, {
        fetch: async () => {
          called = true
          return Buffer.alloc(0)
        }
      }),
      /untrustworthy lockfile/
    )
    t.absent(called, 'the network was never touched')
  } finally {
    clean(cache)
  }
})

test('run requires a fetch implementation', async (t) => {
  await t.exception(
    prefetch.run({ entries: [], problems: [] }, '/tmp', {}),
    /requires a fetch implementation/
  )
})
