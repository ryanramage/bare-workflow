'use strict'

// Transfer tests, weighted heavily toward hostile archives.
//
// An archive coming OUT of a sandbox was written by the workload, which is untrusted by
// construction. So the interesting cases are not "does a tar round-trip" but "what happens when the
// tar is trying to write outside its root". Every rejection below is a real technique.

const test = require('brittle')
const tarlib = require('tar-stream')
const fs = require('bare-fs')
const path = require('bare-path')

const transfer = require('../lib/transfer.js')

let counter = 0
function tmp(label) {
  const dir = `/tmp/bw-transfer-${label}-${Date.now()}-${counter++}`
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

// Build a tar containing exactly the entries given, bypassing our own packer -- the point is to
// feed the extractor things our packer would never produce.
function hostile(entries) {
  const pack = tarlib.pack()
  for (const e of entries) {
    const header = { name: e.name, type: e.type || 'file', mode: e.mode }
    if (e.type === 'symlink' || e.type === 'link') header.linkname = e.linkname || '/etc/passwd'
    if (header.type === 'file') pack.entry(header, e.body === undefined ? '' : e.body)
    else pack.entry(header)
  }
  pack.finalize()
  return pack
}

async function rejects(t, entries, pattern, why, opts) {
  const dest = tmp('reject')
  try {
    await transfer.extract(hostile(entries), dest, opts)
    t.fail('should have been rejected: ' + why)
  } catch (err) {
    t.ok(pattern.test(err.message), `${why}\n    got: ${err.message}`)
    // Nothing may have escaped, whatever else happened.
    const links = []
    const walk = (dir) => {
      for (const n of fs.readdirSync(dir)) {
        const p = path.join(dir, n)
        const st = fs.lstatSync(p)
        if (st.isSymbolicLink()) links.push(p)
        else if (st.isDirectory()) walk(p)
      }
    }
    try {
      walk(dest)
    } catch {}
    t.alike(links, [], 'no symlink was created')
  } finally {
    clean(dest)
  }
}

// --- the happy path --------------------------------------------------------------------

test('a directory tree round-trips', async (t) => {
  const src = tmp('src')
  const dest = tmp('dest')
  try {
    fs.mkdirSync(src + '/sub/deeper', { recursive: true })
    fs.writeFileSync(src + '/a.txt', 'hello')
    fs.writeFileSync(src + '/sub/b.txt', 'world')
    fs.writeFileSync(src + '/sub/deeper/c.bin', Buffer.from([0, 1, 2, 255]))

    const result = await transfer.extract(transfer.pack(src), dest)
    t.is(result.files, 3)
    t.is(fs.readFileSync(dest + '/a.txt', 'utf8'), 'hello')
    t.is(fs.readFileSync(dest + '/sub/b.txt', 'utf8'), 'world')
    t.alike([...fs.readFileSync(dest + '/sub/deeper/c.bin')], [0, 1, 2, 255], 'binary survives')
  } finally {
    clean(src, dest)
  }
})

test('packing is deterministic', async (t) => {
  // Two runs of the same tree must produce identical bytes, so an artifact digest means something.
  const src = tmp('src')
  try {
    fs.writeFileSync(src + '/b', 'two')
    fs.writeFileSync(src + '/a', 'one')
    const collect = (stream) =>
      new Promise((resolve) => {
        const chunks = []
        stream.on('data', (c) => chunks.push(c))
        stream.on('end', () => resolve(Buffer.concat(chunks)))
      })
    const [first, second] = [await collect(transfer.pack(src)), await collect(transfer.pack(src))]
    t.alike(first, second, 'identical archives')
  } finally {
    clean(src)
  }
})

test('symlinks are skipped on the way out, not followed', async (t) => {
  // Following them would let a build smuggle out anything the sandbox could read by planting a link.
  const src = tmp('src')
  const dest = tmp('dest')
  try {
    fs.writeFileSync(src + '/real.txt', 'real')
    fs.symlinkSync('/etc/passwd', src + '/escape')
    fs.symlinkSync('real.txt', src + '/alias')

    const packer = transfer.pack(src)
    const result = await transfer.extract(packer, dest)
    t.is(result.files, 1, 'only the real file was packed')
    t.alike(fs.readdirSync(dest), ['real.txt'])
    t.is(packer.stats.skipped.length, 2, 'and the skips were recorded, not silent')
  } finally {
    clean(src, dest)
  }
})

test('a glob selects what to pack', async (t) => {
  const src = tmp('src')
  const dest = tmp('dest')
  try {
    fs.mkdirSync(src + '/out', { recursive: true })
    fs.writeFileSync(src + '/out/app.bin', 'x')
    fs.writeFileSync(src + '/out/notes.txt', 'y')
    const result = await transfer.extract(
      transfer.pack(src, { match: (rel) => rel.endsWith('.bin') }),
      dest
    )
    t.is(result.files, 1)
    t.alike(fs.readdirSync(dest + '/out'), ['app.bin'])
  } finally {
    clean(src, dest)
  }
})

// --- hostile archives ------------------------------------------------------------------

test('symlink entries are refused', async (t) => {
  await rejects(
    t,
    [{ name: 'passwd', type: 'symlink', linkname: '/etc/passwd' }],
    /forbidden type/,
    'symlink to an absolute path'
  )
  await rejects(
    t,
    [{ name: 'up', type: 'symlink', linkname: '../../../../home/ryan' }],
    /forbidden type/,
    'symlink climbing out'
  )
})

test('hardlinks, fifos and devices are refused', async (t) => {
  await rejects(
    t,
    [{ name: 'hard', type: 'link', linkname: '/etc/passwd' }],
    /forbidden type/,
    'hardlink'
  )
  await rejects(t, [{ name: 'pipe', type: 'fifo' }], /forbidden type/, 'fifo')
  await rejects(
    t,
    [{ name: 'dev', type: 'character-device' }],
    /forbidden type/,
    'character device'
  )
  await rejects(t, [{ name: 'blk', type: 'block-device' }], /forbidden type/, 'block device')
})

test('path traversal is refused', async (t) => {
  await rejects(t, [{ name: '../escaped.txt', body: 'x' }], /escapes its root/, 'leading ..')
  await rejects(t, [{ name: 'a/../../escaped.txt', body: 'x' }], /escapes its root/, 'embedded ..')
  await rejects(
    t,
    [{ name: '../../../../home/ryan/.bashrc', body: 'x' }],
    /escapes its root/,
    'deep climb'
  )
})

test('absolute paths are refused', async (t) => {
  await rejects(t, [{ name: '/etc/passwd', body: 'x' }], /is absolute/, 'unix absolute')
  await rejects(t, [{ name: 'C:/Windows/system32/x', body: 'x' }], /is absolute/, 'windows drive')
})

test('control characters in names are refused', async (t) => {
  await rejects(t, [{ name: 'evil\nname.txt', body: 'x' }], /control character/, 'newline')
  await rejects(t, [{ name: 'evil\rname.txt', body: 'x' }], /control character/, 'carriage return')
})

test('Windows-reserved names are refused', async (t) => {
  // Free to check now; saves a baffling failure the first time an artifact lands on a Windows peer.
  await rejects(t, [{ name: 'CON', body: 'x' }], /Windows-reserved/, 'CON')
  await rejects(t, [{ name: 'sub/nul.txt', body: 'x' }], /Windows-reserved/, 'nul.txt')
  await rejects(t, [{ name: 'com1.dat', body: 'x' }], /Windows-reserved/, 'com1.dat')
})

test('case-insensitive collisions are refused', async (t) => {
  // On Linux these are two files; on a mac or Windows peer one silently overwrites the other.
  await rejects(
    t,
    [
      { name: 'Foo.txt', body: 'a' },
      { name: 'foo.txt', body: 'b' }
    ],
    /collide case-insensitively/,
    'Foo.txt vs foo.txt'
  )
})

test('over-long and over-deep paths are refused', async (t) => {
  await rejects(t, [{ name: 'a'.repeat(2000), body: 'x' }], /exceeds 1024 characters/, 'long name')
  await rejects(
    t,
    [{ name: Array(40).fill('d').join('/') + '/f', body: 'x' }],
    /nested deeper/,
    'deep tree'
  )
})

test('entry-count and byte caps are enforced', async (t) => {
  const many = Array.from({ length: 12 }, (_, i) => ({ name: `f${i}`, body: 'x' }))
  await rejects(t, many, /more than 10 entries/, 'entry cap', { maxEntries: 10 })

  const big = [{ name: 'big', body: 'x'.repeat(4096) }]
  await rejects(t, big, /larger than 1024 bytes/, 'per-file cap', { maxFileBytes: 1024 })
  await rejects(
    t,
    [
      { name: 'a', body: 'x'.repeat(800) },
      { name: 'b', body: 'x'.repeat(800) }
    ],
    /exceeds 1024 bytes in total/,
    'total cap',
    { maxBytes: 1024 }
  )
})

test('exactly one mode bit survives the archive: owner-execute', async (t) => {
  // Two requirements that pull against each other, so both are pinned here.
  //
  // A setuid bit in an artifact must never reach the host -- but a distributable that comes back
  // non-executable is not a distributable, and that is the entire point of the artifact store.
  // So one bit is honoured and everything else is discarded, rather than the mode being carried
  // through and sanitised.
  const dest = tmp('dest')
  try {
    await transfer.extract(
      hostile([
        { name: 'x.sh', body: '#!/bin/sh\n', mode: 0o4777 },
        { name: 'data.json', body: '{}', mode: 0o666 }
      ]),
      dest
    )

    const exe = fs.statSync(dest + '/x.sh').mode & 0o7777
    t.absent(exe & 0o4000, 'setuid stripped')
    t.absent(exe & 0o2000, 'setgid stripped')
    t.absent(exe & 0o1000, 'sticky stripped')
    t.is(
      exe & 0o777,
      0o755,
      'executable, but only ever 0755 -- never the archive world-writable 777'
    )

    const plain = fs.statSync(dest + '/data.json').mode & 0o7777
    t.is(plain & 0o777, 0o644, 'a non-executable entry stays non-executable')
  } finally {
    clean(dest)
  }
})

test('an executable round-trips, so a distributable is still runnable', async (t) => {
  // The concrete failure this guards: `bare-build` produces a binary, the artifact store carries it
  // to an assemble job, and `pear-build` mirrors it into by-arch/. If the execute bit is dropped
  // anywhere along that path the release folder ships files nobody can run, and nothing fails until
  // a user double-clicks.
  const src = tmp('src')
  const dest = tmp('dest')
  try {
    fs.mkdirSync(src, { recursive: true })
    fs.writeFileSync(src + '/app', '#!/bin/sh\necho hi\n', { mode: 0o755 })
    fs.writeFileSync(src + '/README', 'not executable\n', { mode: 0o644 })

    await transfer.extract(transfer.pack(src), dest)

    t.ok(fs.statSync(dest + '/app').mode & 0o100, 'the binary is executable on the far side')
    t.absent(fs.statSync(dest + '/README').mode & 0o111, 'and a data file did not become one')
  } finally {
    clean(src, dest)
  }
})

test('extraction refuses a non-empty destination', (t) => {
  // Unpacking over existing content lets an archive replace files that were already there, which is
  // a different and worse operation than "unpack this".
  const dest = tmp('dest')
  try {
    fs.writeFileSync(dest + '/already-here', 'x')
    t.exception(() => transfer.freshDir(dest), /not empty/)
    const fresh = dest + '/child'
    t.execution(() => transfer.freshDir(fresh), 'a missing directory is created')
    t.ok(fs.statSync(fresh).isDirectory())
  } finally {
    clean(dest)
  }
})

test('checkName normalizes without allowing escape', (t) => {
  t.is(transfer.checkName('a/./b.txt', transfer.DEFAULTS), 'a/b.txt', 'single dots collapse')
  t.is(transfer.checkName('./a.txt', transfer.DEFAULTS), 'a.txt')
  t.is(transfer.checkName('a//b.txt', transfer.DEFAULTS), 'a/b.txt', 'empty segments collapse')
  t.exception(() => transfer.checkName('.', transfer.DEFAULTS), /empty after normalization/)
  t.exception(() => transfer.checkName('', transfer.DEFAULTS), /no name/)
})
