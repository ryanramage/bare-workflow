'use strict'

// Store tests.
//
// The interesting property is that the Store knows only "a drive". `localdrive` and `hyperdrive`
// share a surface, so v1 passes a Localdrive and the farm later passes a Hyperdrive without this
// code changing -- at which point artifact return from a peer is a mirror rather than a protocol.
// The fake drive below exists to prove that independence is real and not just claimed.

const test = require('brittle')
const fs = require('bare-fs')
const { Store, localStore } = require('../lib/store')

let n = 0
function tmp(label) {
  const dir = `/tmp/bw-store-${label}-${Date.now()}-${n++}`
  fs.mkdirSync(dir, { recursive: true })
  return dir
}
const clean = (...dirs) => {
  for (const d of dirs) {
    try {
      fs.rmSync(d, { recursive: true, force: true })
    } catch {}
  }
}

// Minimal in-memory stand-in for the drive surface the Store uses.
function fakeDrive() {
  const map = new Map()
  return {
    map,
    // `executable` is part of the drive surface -- localdrive and hyperdrive both take it on put and
    // report it on entries -- so the fake models it too, or it would prove less than it claims.
    async put(key, buf, opts = {}) {
      map.set(key, { buf, executable: !!opts.executable })
    },
    async get(key) {
      const e = map.get(key)
      return e ? e.buf : null
    },
    async *list(prefix) {
      for (const key of [...map.keys()].sort()) {
        if (!key.startsWith(prefix)) continue
        const e = map.get(key)
        yield { key, value: { blob: e.buf, executable: e.executable } }
      }
    }
  }
}

test('the store is drive-agnostic', async (t) => {
  // Same assertions, an entirely different backend. This is the property the farm depends on.
  const src = tmp('src')
  const out = tmp('out')
  try {
    fs.writeFileSync(src + '/a.txt', 'alpha')
    const store = new Store({ drive: fakeDrive(), runId: 'r1' })
    const put = await store.put('app', src)
    t.is(put.files, 1)
    const got = await store.get('app', out)
    t.is(got.files, 1)
    t.is(fs.readFileSync(out + '/a.txt', 'utf8'), 'alpha')
  } finally {
    clean(src, out)
  }
})

test('a nested tree round-trips through a Localdrive', async (t) => {
  const root = tmp('drive')
  const src = tmp('src')
  const out = tmp('out')
  try {
    fs.mkdirSync(src + '/sub/deeper', { recursive: true })
    fs.writeFileSync(src + '/a.txt', 'alpha')
    fs.writeFileSync(src + '/sub/b.txt', 'beta')
    fs.writeFileSync(src + '/sub/deeper/c.bin', Buffer.from([1, 2, 3]))

    const store = localStore({ root, runId: 'run-1' })
    const put = await store.put('app-linux-x64', src)
    t.is(put.files, 3)
    t.is(put.bytes, 5 + 4 + 3)

    const got = await store.get('app-linux-x64', out)
    t.is(got.files, 3)
    t.is(fs.readFileSync(out + '/sub/b.txt', 'utf8'), 'beta')
    t.alike([...fs.readFileSync(out + '/sub/deeper/c.bin')], [1, 2, 3], 'binary survives the drive')
  } finally {
    clean(root, src, out)
  }
})

test('runs are isolated from each other', async (t) => {
  // Two runs of the same workflow produce the same artifact NAME; without the run id in the key the
  // second would overwrite the first, which matters the moment anything is retained or replicated.
  const root = tmp('drive')
  const a = tmp('a')
  const b = tmp('b')
  const out = tmp('out')
  try {
    fs.writeFileSync(a + '/f', 'from run one')
    fs.writeFileSync(b + '/f', 'from run two')
    await localStore({ root, runId: 'run-1' }).put('app', a)
    await localStore({ root, runId: 'run-2' }).put('app', b)

    await localStore({ root, runId: 'run-1' }).get('app', out)
    t.is(fs.readFileSync(out + '/f', 'utf8'), 'from run one', 'run 1 is intact')

    const list1 = await localStore({ root, runId: 'run-1' }).list()
    const list2 = await localStore({ root, runId: 'run-2' }).list()
    t.alike(
      list1.map((x) => x.name),
      ['app']
    )
    t.alike(
      list2.map((x) => x.name),
      ['app']
    )
  } finally {
    clean(root, a, b, out)
  }
})

test('list and has report what a run produced', async (t) => {
  const root = tmp('drive')
  const src = tmp('src')
  try {
    fs.writeFileSync(src + '/x', 'x')
    const store = localStore({ root, runId: 'r' })
    t.absent(await store.has('app'), 'nothing yet')
    await store.put('app', src)
    await store.put('bundle', src)
    t.ok(await store.has('app'))
    t.absent(await store.has('missing'))
    t.alike(
      (await store.list()).map((x) => x.name),
      ['app', 'bundle'],
      'sorted, deterministic'
    )
  } finally {
    clean(root, src)
  }
})

test('artifact names are validated, not sanitized', async (t) => {
  // Names end up in keys and later in filenames on other people's machines. Rewriting one silently
  // makes it hard to find again, so reject instead.
  const root = tmp('drive')
  const src = tmp('src')
  try {
    fs.writeFileSync(src + '/x', 'x')
    const store = localStore({ root, runId: 'r' })
    for (const bad of ['../escape', 'a/b', 'with space', '', '.hidden', 'x'.repeat(200)]) {
      await t.exception(store.put(bad, src), /INVALID_SPEC/, JSON.stringify(bad))
    }
    await t.execution(store.put('app-linux-x64', src), 'a target-suffixed name is fine')
    await t.execution(store.put('bundle.tar', src), 'dots are fine')
  } finally {
    clean(root, src)
  }
})

test('an empty artifact is reported according to if-no-files-found', async (t) => {
  const root = tmp('drive')
  const empty = tmp('empty')
  try {
    const store = localStore({ root, runId: 'r' })
    await t.exception(store.put('app', empty, { ifNoFilesFound: 'error' }), /ARTIFACT_EMPTY/)
    const quiet = await store.put('app', empty, { ifNoFilesFound: 'ignore' })
    t.is(quiet.files, 0, 'ignore mode simply records nothing')
  } finally {
    clean(root, empty)
  }
})

test('fetching a missing artifact is an error, not an empty directory', async (t) => {
  // Silently producing an empty directory would let a downstream job build against nothing.
  const root = tmp('drive')
  const out = tmp('out')
  try {
    await t.exception(localStore({ root, runId: 'r' }).get('nope', out), /ARTIFACT_MISSING/)
  } finally {
    clean(root, out)
  }
})

test('the store refuses to be constructed without what it needs', (t) => {
  t.exception(() => new Store({ runId: 'r' }), /requires a drive/)
  t.exception(() => new Store({ drive: fakeDrive() }), /requires a runId/)
})

test('an executable survives the store, on any drive', async (t) => {
  // The end-to-end failure this closes: bare-build produces a binary, the store carries it to an
  // assemble job, pear-build mirrors it into by-arch/. The store used to write every file 0644, so
  // a release folder shipped binaries nobody could run -- and nothing failed until a user tried.
  for (const [label, drive] of [
    ['fake', fakeDrive()],
    ['localdrive', null]
  ]) {
    const src = tmp('exe-src')
    const out = tmp('exe-out')
    try {
      fs.writeFileSync(src + '/app', '#!/bin/sh\n', { mode: 0o755 })
      fs.writeFileSync(src + '/notes.txt', 'plain\n', { mode: 0o644 })

      const store = drive
        ? new Store({ drive, runId: 'r-exe' })
        : localStore({ root: tmp('exe-drive'), runId: 'r-exe' })

      await store.put('app', src)
      await store.get('app', out)

      t.ok(fs.statSync(out + '/app').mode & 0o100, label + ': the binary is executable')
      t.absent(fs.statSync(out + '/notes.txt').mode & 0o111, label + ': a data file is not')
    } finally {
      clean(src, out)
    }
  }
})

test('the execute bit is part of the artifact digest', async (t) => {
  // The attestation binds to the digest, so two trees that differ only in which files are runnable
  // must not collide -- one of them is a working release and the other is not.
  const a = tmp('dig-a')
  const b = tmp('dig-b')
  try {
    fs.writeFileSync(a + '/app', 'same bytes', { mode: 0o755 })
    fs.writeFileSync(b + '/app', 'same bytes', { mode: 0o644 })

    const one = await new Store({ drive: fakeDrive(), runId: 'r' }).put('x', a)
    const two = await new Store({ drive: fakeDrive(), runId: 'r' }).put('x', b)

    t.not(one.digest, two.digest, 'identical content, different artifact')
  } finally {
    clean(a, b)
  }
})

test('put and get agree on the digest, whatever the traversal order', async (t) => {
  // These two names are chosen deliberately: `put` walks depth-first so it yields `a/b` before
  // `a.txt`, while a drive lists keys lexicographically and '.' sorts before '/'. The two orders
  // disagree, so a digest computed from either traversal would differ between writing and reading --
  // and the artifact would look corrupted every time it was fetched.
  const src = tmp('ord-src')
  const out = tmp('ord-out')
  try {
    fs.mkdirSync(src + '/a', { recursive: true })
    fs.writeFileSync(src + '/a/b', 'nested')
    fs.writeFileSync(src + '/a.txt', 'sibling')

    const store = localStore({ root: tmp('ord-drive'), runId: 'r' })
    const put = await store.put('app', src)
    const got = await store.get('app', out)

    t.is(got.digest, put.digest, 'the digest survives the round trip')
    t.ok(put.digest.startsWith('sha256:'))
    t.is(got.files, 2)
  } finally {
    clean(src, out)
  }
})
