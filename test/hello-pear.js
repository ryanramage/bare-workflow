'use strict'

// The distributables stage, end to end.
//
// This is the milestone test for "a Holepunch dev's actual project builds here". It asserts on
// `file(1)` output per target rather than exit codes, because "bare-build exited 0" and "this is a
// runnable arm64 Mach-O" are very different claims — and the gap between them is exactly where
// darwin-arm64 fails.

const test = require('brittle')
const { spawn } = require('bare-subprocess')
const fs = require('bare-fs')
const path = require('bare-path')
const { hostEnv } = require('../lib/host-env.js')

const detect = require('../lib/isolation/detect.js')
const toolchains = require('../lib/toolchains.js')
const targets = require('../lib/targets.js')
const { localStore } = require('../lib/store')
const dht = require('./support/dht.js')
const { need, runId: runIdOf } = require('./support/need.js')

const ROOT = path.join(__dirname, '..')
const BIN = path.join(ROOT, 'bin.js')

function cli(args, timeoutMs = 1800000) {
  return new Promise((resolve) => {
    const proc = spawn(Bare.argv[0], [BIN, ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: hostEnv()
    })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => {
      try {
        proc.kill('SIGKILL')
      } catch {}
    }, timeoutMs)
    proc.stdout.on('data', (c) => {
      stdout += c
    })
    proc.stderr.on('data', (c) => {
      stderr += c
    })
    proc.on('exit', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
  })
}

function fileType(target) {
  return new Promise((resolve) => {
    const proc = spawn('file', ['-b', target], {
      stdio: ['ignore', 'pipe', 'ignore'],
      env: hostEnv()
    })
    let out = ''
    proc.stdout.on('data', (c) => {
      out += c
    })
    proc.on('error', () => resolve(null))
    proc.on('exit', () => resolve(out.trim()))
  })
}

// Skip cleanly unless this machine can actually run the toolchain.
function ready() {
  try {
    // The tier is returned, not just discarded: every `cli(['run', ...])` below has to pass it
    // explicitly, because the CLI's own default minimum is microvm and that is permanently
    // unavailable on macOS. Without it the run exits 78 before doing anything this file asserts on.
    const r = detect.resolve({ min: 'container', image: toolchains.resolve('bare-build').image })
    return { ok: true, tier: r.tier }
  } catch (err) {
    return { ok: false, why: err.message.split('\n')[0] }
  }
}

test('the capability rule is per-target, not per-platform', (t) => {
  // The naive model ("only your own platform") is wrong: bare-build injects a bundle into a prebuilt
  // runtime with bare-lief and never compiles. What actually blocks a target is a signature the host
  // cannot issue.
  const linux = targets.describe({ platform: 'linux', arch: 'x64' })

  t.ok(targets.buildableOn('linux', 'win32-x64'), 'PE injection needs no Windows')
  t.ok(targets.buildableOn('linux', 'win32-arm64'))
  t.ok(targets.buildableOn('linux', 'linux-arm64'), 'a different arch is still just ELF')
  t.ok(
    targets.buildableOn('linux', 'darwin-x64'),
    'the x64 runtime carries no signature to invalidate'
  )

  // The one real exception, and the reason a Mac peer is needed.
  t.absent(targets.buildableOn('linux', 'darwin-arm64'), 'an arm64 Mach-O must be signed to run')
  t.ok(targets.buildableOn('darwin', 'darwin-arm64'), 'and only a Mac can sign it')

  t.ok(linux.unsignable.includes('darwin-arm64'), 'reported as a SIGNING gap, not a build gap')
  t.absent(linux.unsignable.includes('win32-x64'), 'unsigned windows binaries still run')
})

test('an unverified target is declined rather than guessed at', (t) => {
  // apk tooling ships prebuilds for only some hosts; claiming it would fail late and confusingly.
  t.absent(targets.buildableOn('linux', 'android-arm64'))
  t.absent(targets.describe({ platform: 'linux', arch: 'x64' }).targets.includes('android-arm64'))
})

test('the project asserts its own name survives bare-build', (t) => {
  // bare-build lowercases and hyphenates --name; the OTA updater looks the binary up by pkg.name.
  // A mismatch is silent until an update fails, so the project carries the check itself.
  const pkg = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'examples/hello-pear/package.json'), 'utf8')
  )
  const identifier = pkg.name
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
    .toLowerCase()
  t.is(identifier, pkg.name, 'pkg.name is already normalizer-stable')
  for (const script of Object.keys(pkg.scripts)) {
    if (!script.startsWith('make:')) continue
    t.ok(pkg.scripts[script].includes(`--name ${pkg.name} `), `${script} passes --name ${pkg.name}`)
  }
})

test('the upgrade link is asserted, never written', { timeout: 300000 }, async (t) => {
  // The link is compiled into the binary, so a mismatch means the distributable cannot receive
  // updates from the intended release line. Assert before anything runs.
  //
  // "Before anything runs" still means the run has to GET that far: with no usable tier the CLI
  // exits 78 at tier detection and never reaches the upgrade assertion, so this has to skip rather
  // than report a mismatch it never checked.
  const can = ready()
  if (!can.ok) {
    t.comment('skipping: ' + can.why)
    return t.pass('skipped')
  }

  const src = path.join(ROOT, 'examples/hello-pear/package.json')
  const before = fs.readFileSync(src, 'utf8')
  const tmpf = path.join(ROOT, 'examples/.test-mismatch.yml')

  const original = fs.readFileSync(path.join(ROOT, 'examples/hello-pear.yml'), 'utf8')
  fs.writeFileSync(
    tmpf,
    original.replace(
      /upgrade: pear:\/\/\S+/,
      'upgrade: pear://deliberatelywrongxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    )
  )
  try {
    const r = await cli(['run', 'examples/.test-mismatch.yml', '--tier', can.tier], 300000)
    t.is(r.code, 1, 'a mismatch fails the run')
    const blob = r.stdout + r.stderr
    t.ok(/upgrade link mismatch/.test(blob))
    t.ok(/deliberatelywrong/.test(blob), 'quotes the expected link')
    t.ok(
      /kv8bmfbpc9dcxhqmrp8xrxzbjfawcqrpwwx8kwqxeu9dxpcgnwno/.test(blob),
      'and the one actually found'
    )
    t.is(fs.readFileSync(src, 'utf8'), before, 'and the project was NOT modified')
  } finally {
    try {
      fs.unlinkSync(tmpf)
    } catch {}
  }
})

test(
  'five targets cross-build from this one Linux machine, into one deployment folder',
  { timeout: 2400000 },
  async (t) => {
    const can = ready()
    if (!can.ok) {
      t.comment('skipping: ' + can.why)
      return t.pass('skipped')
    }

    const state = '/tmp/bw-test-hp-' + Date.now()
    const out = '/tmp/bw-test-hp-out-' + Date.now()
    // The example carries all three deployment stages, so running it needs an identity and a
    // network. Both are throwaway: a key that exists only for this test, and a DHT on localhost.
    // Nothing here touches a real release line, which is what makes the publish path testable.
    const secrets = '/tmp/bw-test-hp-cfg-' + Date.now() + '.json'
    const netDir = '/tmp/bw-test-hp-net-' + Date.now()
    const PRIMARY_KEY = 'e'.repeat(64)
    let net = null
    try {
      fs.writeFileSync(
        secrets,
        JSON.stringify({ keys: { 'hello-pear': { primaryKey: PRIMARY_KEY } } }),
        { mode: 0o600 }
      )
      if (dht.available()) {
        net = await dht.testnetWithSeeder(Buffer.from(PRIMARY_KEY, 'hex'), 'hello-pear', netDir)
      } else {
        t.comment('no local DHT available; the publish job runs as a dry run')
      }

      const r = await cli([
        'run',
        'examples/hello-pear.yml',
        '--json',
        '--tier',
        can.tier,
        '--concurrency',
        '2',
        '--state',
        state,
        '--config',
        secrets,
        ...(net ? ['--bootstrap', net.address, '--publish'] : [])
      ])
      if (r.code === 78 && /not built/.test(r.stdout + r.stderr)) {
        t.comment('skipping: bare-build toolchain image not built')
        return t.pass('skipped')
      }
      t.is(r.code, 0, 'the run succeeded\n' + r.stderr.slice(0, 600))

      const evs = r.stdout
        .split('\n')
        .filter((l) => l.startsWith('{'))
        .map((l) => JSON.parse(l))

      // darwin-arm64 must be REPORTED, not silently produced: a Linux-built arm64 Mach-O carries a
      // stale signature and Apple Silicon kills it, so shipping one is worse than declining.
      const unsupported = evs
        .filter((e) => e.cmd === 'task' && e.tag === 'unsupported')
        .map((e) => e.data.target)
      t.alike(unsupported, ['darwin-arm64'], 'exactly one target declined, and it is the right one')

      const produced = evs
        .filter((e) => e.cmd === 'artifact' && e.tag === 'out')
        .map((e) => e.data.name)
      t.alike(
        produced.filter((n) => n.startsWith('dist-')).sort(),
        [
          'dist-darwin-x64',
          'dist-linux-arm64',
          'dist-linux-x64',
          'dist-win32-arm64',
          'dist-win32-x64'
        ],
        'five distributables: ' + produced.join(', ')
      )
      t.ok(produced.includes('deployment'), 'and the assembled deployment folder')

      // The real assertion: each binary is genuinely for its target.
      const runId = runIdOf(t, fs, state)
      if (!runId) return
      const store = localStore({ root: state + '/artifacts', runId })
      const expected = {
        // Case-insensitive, and the aarch64/ARM64 spellings are both accepted, because file(1)
        // does not agree with itself across platforms: for the same win32-arm64 binary Linux's
        // file says "PE32+ executable (console) ARM64" and macOS's says "... Aarch64". Pinning one
        // spelling made this fail on a Mac while the binary was perfectly correct -- a property of
        // the test host leaking into an assertion about the artifact.
        'linux-x64': /^ELF .*x86-64/i,
        'linux-arm64': /^ELF .*aarch64/i,
        'win32-x64': /^PE32\+ .*x86-64/i,
        'win32-arm64': /^PE32\+ .*(ARM64|Aarch64)/i,
        'darwin-x64': /^Mach-O .*x86_64/i
      }
      for (const [target, pattern] of Object.entries(expected)) {
        const dir = path.join(out, target)
        await store.get('dist-' + target, dir)
        const names = fs.readdirSync(dir)
        t.ok(names.length > 0, target + ' produced a file')
        if (!names.length) continue
        const binary = path.join(dir, names[0])
        const type = await fileType(binary)
        if (type === null) {
          t.comment('file(1) unavailable; falling back to magic bytes')
          const magic = fs.readFileSync(binary).subarray(0, 4)
          t.ok(magic.length === 4, target + ' has content')
          continue
        }
        t.ok(pattern.test(type), `${target}: ${type.slice(0, 60)}`)
      }

      // Stage 2: the deployment folder pear actually stages. Its shape is a contract with two other
      // tools -- `pear-runtime-updater` fetches `/by-arch/<host>/app/<name>` and `pear-install`
      // derives the installed binary name the same way -- so the layout AND the filename are both
      // asserted, not just "some files came back".
      const deploy = path.join(out, 'deployment')
      await store.get('deployment', deploy)

      const files = []
      const walk = (dir, prefix) => {
        for (const name of fs.readdirSync(dir)) {
          const p = path.join(dir, name)
          if (fs.statSync(p).isDirectory()) walk(p, prefix + name + '/')
          else files.push(prefix + name)
        }
      }
      walk(deploy, '')

      const root = 'hello-pear-1.0.0/'
      t.ok(files.includes(root + 'package.json'), 'pear-build copied the manifest')
      for (const [target, ext] of [
        ['linux-x64', ''],
        ['linux-arm64', ''],
        ['win32-x64', '.exe'],
        ['win32-arm64', '.exe'],
        ['darwin-x64', '']
      ]) {
        t.ok(
          files.includes(`${root}by-arch/${target}/app/hello-pear${ext}`),
          `${target} is in by-arch/ under the name the updater looks for`
        )
      }
      t.absent(
        files.some((f) => f.includes('by-arch/darwin-arm64/')),
        'and Apple Silicon is absent rather than present-but-broken'
      )

      // The execute bit has now survived: sandbox -> tar -> store -> tar -> sandbox -> Localdrive
      // mirror -> tar -> store -> host. Six hops, any one of which could have flattened it.
      t.ok(
        fs.statSync(path.join(deploy, root, 'by-arch/linux-x64/app/hello-pear')).mode & 0o100,
        'the staged binary is still executable'
      )

      // Stage 3: the publish. This is the end of the line the docs describe -- make distributables,
      // build the deployment directory, stage -- so the assertion is that a real `pear://` link came
      // out of it, and that the record binds that link to the exact bytes that were published.
      // need(), not a bare find(): `t.ok(published)` records a failure but does NOT stop the test,
      // so the next line dereferenced undefined and took the whole suite down with an uncaught
      // TypeError. Seen for real -- this test passes in isolation but had not run its publish job
      // during one full-suite run, and the crash hid every test after it.
      const published = need(t, evs, (e) => e.cmd === 'publish' && e.tag === 'done', 'publish/done')
      const pub = published.data || {}
      t.ok(/^pear:\/\/[a-z0-9]{52}$/.test(pub.link || ''), 'a real link: ' + pub.link)
      t.is(pub.live, !!net, 'live only when this machine had a network and --publish')
      if (net) {
        t.is(pub.link, net.link, 'and it is the drive the seeder was watching')
        t.ok(pub.snapshot && pub.snapshot.after.length > 0, 'the snapshot moved forward')
      }

      const record = JSON.parse(
        fs.readFileSync(path.join(state, 'runs', runId, 'stage-host.json'), 'utf8')
      )
      t.is(record.isolation.tier, 'trusted', 'the record says plainly that this was not sandboxed')
      t.is(
        record.inputs.artifactDigest,
        (await store.get('deployment', out + '-verify')).digest,
        'and binds the link to the digest of the tree that was staged'
      )
      t.absent(
        JSON.stringify(record).includes(PRIMARY_KEY),
        'the key never reaches the attestation -- only the NAME of the config entry does'
      )
    } finally {
      if (net) await net.destroy()
      for (const d of [state, out, out + '-verify', netDir]) {
        try {
          fs.rmSync(d, { recursive: true, force: true })
        } catch {}
      }
      try {
        fs.rmSync(secrets, { force: true })
      } catch {}
    }
  }
)
