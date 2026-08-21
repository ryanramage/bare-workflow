'use strict'

// Publishing: the trust boundary, tested from both sides.
//
// Two halves, and the first matters more than the second. The parse-time half asserts what the
// schema REFUSES, because a publish job is the one place in this system where untrusted input sits
// next to a private key -- so the interesting property is not that a correct workflow works, it is
// that a plausible-looking wrong one is rejected before anything runs. The integration half then
// proves the whole three-stage flow actually reaches a `pear://` link, against a real DHT stood up
// on this machine with a throwaway key.

const test = require('brittle')
const { spawn } = require('bare-subprocess')
const fs = require('bare-fs')
const path = require('bare-path')
const env = require('bare-env')

const schema = require('../lib/schema')
const config = require('../lib/config.js')
const driver = require('../lib/publish/pear-ci.js')
const publish = require('../lib/publish')
const dht = require('./support/dht.js')

const ROOT = path.join(__dirname, '..')
const BIN = path.join(ROOT, 'bin.js')

let n = 0
function tmp(label) {
  const dir = `/tmp/bw-pub-${label}-${Date.now()}-${n++}`
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

// A workflow whose build job produces `deployment`, plus whatever publish block is under test.
function workflow(publishBlock, extra = '') {
  return `version: 1
name: pub
jobs:
  build:
    targets: [host]
    artifacts:
      out:
        - name: deployment
          path: build/**
    steps:
      - run: mkdir -p build && printf 'x\\n' > build/app
  stage:
    needs: build
${extra}    publish:
${publishBlock}
`
}

function refused(t, src, pattern, why) {
  try {
    schema.parse(src, { filename: 'pub.yml' })
    t.fail('should have been refused: ' + why)
  } catch (err) {
    t.ok(pattern.test(err.message), `${why}\n    got: ${err.message}`)
  }
}

// --- what the schema refuses -----------------------------------------------------------

test('a publish job cannot contain steps', (t) => {
  // The load-bearing refusal. A publish job runs with the key in the runner's hands and no sandbox
  // around it, so there must be nowhere inside it for a command to appear -- not "commands are
  // discouraged", nowhere.
  refused(
    t,
    workflow(
      '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n',
      '    steps:\n      - run: cat ~/.config/bare-workflow/config.json\n'
    ),
    /publish job runs no user code/,
    'steps are refused'
  )
})

test('a publish job cannot fetch, check out, or pick an image', (t) => {
  // Each of these would be accepted-and-ignored by a laxer schema, which is the worst outcome: the
  // author believes the field did something.
  for (const [key, value, pattern] of [
    ['prefetch', '[npm]', /installs nothing/],
    ['source', './project', /no workspace/],
    ['toolchain', 'node', /runs on the runner, not in an image/],
    ['tier', 'container', /not sandboxed/],
    ['targets', '[linux-x64]', /runs once, on the runner/],
    ['env', '{ A: b }', /runs no commands/]
  ]) {
    refused(
      t,
      workflow(
        '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n',
        `    ${key}: ${value}\n`
      ),
      pattern,
      `${key}: is refused with a reason`
    )
  }
})

test('a key must be a NAME, never the key itself', (t) => {
  // The check is on the shape of the value rather than on the author's care, because the cost of
  // missing it is a private key committed to a repository.
  refused(
    t,
    workflow(
      `      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: ${'a'.repeat(64)}\n`
    ),
    /looks like a key, not a key NAME/,
    'a 64-hex value is refused'
  )
  refused(
    t,
    workflow(
      '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: "{{ env.SECRET }}"\n'
    ),
    /cannot be interpolated/,
    'and so is an interpolated one -- a build must not choose its own publish target'
  )
})

test('the artifact must be produced upstream in this same run', (t) => {
  // The store is per-run, so an artifact name that no earlier job produces can never resolve. Caught
  // here, it is a typo; caught at publish time, it is a full build wasted.
  refused(
    t,
    workflow(
      '      driver: pear-ci\n      artifact: deploymnet\n      name: app\n      key: app\n'
    ),
    /no job upstream of "stage" produces an artifact named "deploymnet".*did you mean "deployment"/s,
    'a misspelled artifact is caught with a suggestion'
  )
})

test('a publish job must declare what it depends on', (t) => {
  const src = `version: 1
jobs:
  stage:
    publish:
      driver: pear-ci
      artifact: deployment
      name: app
      key: app
`
  refused(t, src, /needs.*is required on a publish job/s, 'without needs it would race the build')
})

test('an unknown driver is named, with the known ones listed', (t) => {
  refused(
    t,
    workflow(
      '      driver: pear-stage\n      artifact: deployment\n      name: app\n      key: app\n'
    ),
    /unknown publish driver "pear-stage".*known: pear-ci/s,
    'and no driver is invented'
  )
  t.alike(publish.names(), ['pear-ci'], 'deliberately one driver: no provision, multisig or seed')
})

test('dry-run is the default', (t) => {
  // Publishing is the only irreversible thing a run does, so the safe value must be the one you get
  // by not thinking about it.
  const w = schema.parse(
    workflow('      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n')
  )
  t.is(w.jobs.stage.publish.dryRun, true, 'omitted means dry-run')

  const explicit = schema.parse(
    workflow(
      '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n      dry-run: false\n'
    )
  )
  t.is(explicit.jobs.stage.publish.dryRun, false, 'and it takes an explicit false')
})

// --- runner configuration --------------------------------------------------------------

test('a config file readable by other users is refused', (t) => {
  // Not a style preference: this file holds a private key, so on a shared machine a group-readable
  // one is already leaked. Refusing is the only honest response.
  const dir = tmp('cfg')
  const file = path.join(dir, 'config.json')
  try {
    fs.writeFileSync(file, JSON.stringify({ keys: { app: { primaryKey: 'a'.repeat(64) } } }), {
      mode: 0o644
    })
    try {
      config.load(file)
      t.fail('a 0644 config should be refused')
    } catch (err) {
      t.is(err.code, 'CONFIG_INSECURE')
      t.ok(/chmod 600/.test(err.message), 'and the message contains the fix')
    }

    fs.chmodSync(file, 0o600)
    const c = config.load(file)
    t.alike(c.names(), ['app'], 'at 0600 it loads')
    t.is(c.secret('app', 'primaryKey').length, 64)
    t.absent(JSON.stringify(c.names()).includes('a'.repeat(64)), 'names() never exposes a value')
  } finally {
    clean(dir)
  }
})

test('a wrong-length primary key is refused before it derives the wrong drive', (t) => {
  // The failure this prevents is the quiet one: a short key still derives A drive, so the publish
  // succeeds against an address nobody is listening on.
  try {
    driver.parsePrimaryKey('abcd', 'test')
    t.fail('should refuse')
  } catch (err) {
    t.is(err.code, 'PUBLISH_REFUSED')
    t.ok(/64 hex characters/.test(err.message))
    t.ok(/DIFFERENT drive/.test(err.message), 'and says why it matters')
  }
})

// --- the whole flow, against a real DHT ------------------------------------------------

test('publishing with nobody seeding times out, and says so', { timeout: 120000 }, async (t) => {
  if (!dht.available()) {
    t.comment('skipping: pear-ci test dependencies not installed')
    return t.pass('skipped')
  }
  const createTestnet = require('@hyperswarm/testnet')
  const dir = tmp('nopeer')
  const testnet = await createTestnet(3)
  try {
    fs.writeFileSync(path.join(dir, 'app'), 'v1\n')
    await driver.publish({
      primaryKey: 'b'.repeat(64),
      name: 'nopeer',
      dir,
      snapshot: path.join(dir, '..', 'snap-nopeer.json'),
      storage: path.join(dir, '..', 'store-nopeer'),
      dryRun: false,
      bootstrap: testnet.bootstrap,
      timeoutMs: 8000
    })
    t.fail('should not have completed with no peer')
  } catch (err) {
    t.is(err.code, 'PUBLISH_FAILED')
    // The diagnosis, not just the symptom. Unwrapped, pear-ci polls forever with no output at all,
    // which is the single most confusing way for a release to fail.
    t.ok(/nothing is seeding/.test(err.message), 'names the actual cause')
    t.ok(/pear seed/.test(err.message), 'and what fixes it')
    t.ok(/pear:\/\//.test(err.message), 'and which drive it was trying to reach')
  } finally {
    await testnet.destroy()
    clean(dir)
  }
})

test('the full flow reaches a pear:// link, twice', { timeout: 300000 }, async (t) => {
  if (!dht.available()) {
    t.comment('skipping: pear-ci test dependencies not installed')
    return t.pass('skipped')
  }
  const base = tmp('flow')
  const net = await dht.testnetWithSeeder(Buffer.from('c'.repeat(64), 'hex'), 'flow-app', base)
  try {
    const snapshot = path.join(base, 'state', 'snapshot.json')
    const dir = path.join(base, 'dist')
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, 'app'), 'v1\n', { mode: 0o755 })

    const opts = {
      primaryKey: 'c'.repeat(64),
      name: 'flow-app',
      dir,
      snapshot,
      dryRun: false,
      bootstrap: net.bootstrap,
      timeoutMs: 90000
    }

    const first = await driver.publish({ ...opts, storage: path.join(base, 'store1') })
    t.ok(/^pear:\/\/[a-z0-9]{52}$/.test(first.link), 'a real link: ' + first.link)
    t.alike(first.diffs, [{ op: 'add', key: '/app' }], 'and the diff says what went in')
    t.ok(first.snapshot.after.length > 0, 'the snapshot moved forward')

    // The second publish is the one that proves the snapshot is doing its job. With fresh throwaway
    // storage, the ONLY thing that stops this from forking the drive is the snapshot telling it what
    // lengths to catch up to first. A fork would show up as another `add` at length 0.
    fs.writeFileSync(path.join(dir, 'app'), 'v2\n', { mode: 0o755 })
    const second = await driver.publish({ ...opts, storage: path.join(base, 'store2') })

    t.is(second.link, first.link, 'the same drive -- identity is derived from the key, not the run')
    t.alike(second.diffs, [{ op: 'change', key: '/app' }], 'a change, not a second add')
    t.is(
      second.snapshot.before.length,
      first.snapshot.after.length,
      'and it resumed exactly where the previous run left off'
    )
    t.ok(second.snapshot.after.length > second.snapshot.before.length, 'then moved forward again')
  } finally {
    await net.destroy()
    clean(base)
  }
})

test('a dry run reports the link and changes nothing', { timeout: 120000 }, async (t) => {
  if (!dht.available()) {
    t.comment('skipping: pear-ci test dependencies not installed')
    return t.pass('skipped')
  }
  const createTestnet = require('@hyperswarm/testnet')
  const base = tmp('dry')
  const testnet = await createTestnet(3)
  try {
    const dir = path.join(base, 'dist')
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, 'app'), 'v1\n')

    const snapshot = path.join(base, 'state', 'snapshot.json')
    const r = await driver.publish({
      primaryKey: 'd'.repeat(64),
      name: 'dry-app',
      dir,
      snapshot,
      storage: path.join(base, 'store'),
      dryRun: true,
      bootstrap: testnet.bootstrap,
      timeoutMs: 60000
    })

    // A dry run that cannot tell you the target is not much of a preview, so the link is still
    // reported -- it is derived from the key, and deriving it writes nothing.
    t.ok(/^pear:\/\//.test(r.link), 'the link is still reported')
    t.is(r.dryRun, true)
    t.alike(r.diffs, [{ op: 'add', key: '/app' }], 'the diff is computed')
    t.is(r.snapshot.after.length, 0, 'and nothing was actually written')
  } finally {
    await testnet.destroy()
    clean(base)
  }
})

// --- through the CLI -------------------------------------------------------------------

function cli(args, timeoutMs = 300000) {
  return new Promise((resolve) => {
    const proc = spawn(Bare.argv[0], [BIN, ...args], {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR }
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
    proc.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr })
    })
  })
}

test('`validate` says a publish job is not sandboxed, and whether it is live', async (t) => {
  // Whoever reviews a workflow should not have to know that `dry-run` defaults to true, nor infer
  // from the absence of `steps:` that this job runs outside the sandbox.
  const dir = tmp('val')
  try {
    const file = path.join(dir, 'wf.yml')
    fs.writeFileSync(
      file,
      workflow(
        '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n'
      )
    )
    const r = await cli(['validate', file])
    t.is(r.code, 0)
    t.ok(/publish deployment -> app via pear-ci/.test(r.stdout))
    t.ok(/\(dry-run\)/.test(r.stdout), 'says it would not publish')
    t.ok(/not sandboxed/.test(r.stdout), 'and that it is trusted')

    fs.writeFileSync(
      file,
      workflow(
        '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n      dry-run: false\n'
      )
    )
    const live = await cli(['validate', file])
    t.ok(/LIVE, needs --publish/.test(live.stdout), 'and a live one is called out')
  } finally {
    clean(dir)
  }
})

test('a missing key is refused BEFORE anything is built', { timeout: 120000 }, async (t) => {
  // The ordering is the point. A publish job is the last thing in a release pipeline, so without
  // this the failure lands after six targets have been cross-built -- twenty minutes of correct work
  // discarded over a line of JSON. It is also exit 78 (EX_CONFIG), not 1: the workflow is fine, the
  // machine is not.
  const detect = require('../lib/isolation/detect.js')
  const toolchains = require('../lib/toolchains.js')
  try {
    detect.resolve({ min: 'container', image: toolchains.resolve('bare').image })
  } catch (err) {
    t.comment('skipping: ' + err.message.split('\n')[0])
    return t.pass('skipped')
  }

  const dir = tmp('preflight')
  try {
    const file = path.join(dir, 'wf.yml')
    fs.writeFileSync(
      file,
      workflow(
        '      driver: pear-ci\n      artifact: deployment\n      name: app\n      key: app\n'
      )
    )
    const r = await cli([
      'run',
      file,
      '--state',
      path.join(dir, 'state'),
      '--config',
      '/nonexistent/bw.json'
    ])

    t.is(r.code, 78, 'EX_CONFIG: the host is not configured, the workflow is fine')
    const blob = r.stdout + r.stderr
    t.ok(/no runner config at \/nonexistent\/bw\.json/.test(blob), 'names the file it looked for')
    t.ok(/publish job: stage \(key: app\)/.test(blob), 'and which job needed it')
    t.absent(/build:host/.test(blob), 'and nothing was built first')
  } finally {
    clean(dir)
  }
})

test('a configured key is never echoed anywhere', { timeout: 120000 }, async (t) => {
  // Worth asserting rather than assuming: the whole design rests on the secret existing in exactly
  // one place, and a stray log line or attestation field would quietly undo that.
  const dir = tmp('leak')
  const SECRET = 'f'.repeat(64)
  try {
    const cfgFile = path.join(dir, 'config.json')
    fs.writeFileSync(cfgFile, JSON.stringify({ keys: { app: { primaryKey: SECRET } } }), {
      mode: 0o600
    })
    const c = config.load(cfgFile)

    // Every accessor that is not `secret()` itself must be safe to print.
    t.absent(JSON.stringify(c.names()).includes(SECRET), 'names() is safe')
    t.absent(JSON.stringify(c).includes(SECRET), 'and so is the object itself')
    t.absent(String(c).includes(SECRET), 'and its string form')
    t.is(c.secret('app', 'primaryKey'), SECRET, 'while the explicit accessor still works')
  } finally {
    clean(dir)
  }
})
