'use strict'

// The shared Sandbox lifecycle suite.
//
// One set of assertions, run against every launcher available on the machine: the test-only local
// subprocess, a hardened container, and a krun microVM. That is the whole point -- these are not
// three suites that happen to look alike, they are the same suite, so a protocol regression cannot
// hide behind "well, it passed under the fast launcher".
//
// Assertions here are deliberately PROTOCOL-level and tier-agnostic. Tier-specific privilege facts
// (capabilities, uid maps, syscall denials) belong to test/escape/, which knows that the boundary
// is the kernel for a container and the VM for a microVM. The one exception is uid, which the
// launcher descriptor declares, because krun legitimately runs the workload as uid 0.

const { create: sandbox } = require('../../lib/sandbox.js')

function collect(run) {
  let out = ''
  let err = ''
  run.stdout.on('data', (c) => {
    out += c
  })
  run.stderr.on('data', (c) => {
    err += c
  })
  return () => ({ out, err })
}

// Register the suite for one launcher. `test` is brittle's test function.
function lifecycleSuite(test, descriptor) {
  const { name, make } = descriptor
  // Isolated tiers get a real workspace at /w/src (the agent creates it at startup, because the
  // tmpfs arrives empty). The local launcher runs on the host, where /w does not exist.
  const CWD = descriptor.cwd || undefined
  const tag = (s) => `[${name}] ${s}`

  async function withBox(opts, fn) {
    const launcher = make()
    const box = sandbox({ launcher, ...opts })
    try {
      await box.prepare()
      return await fn(box, launcher)
    } finally {
      await box.dispose()
    }
  }

  const step = (run, extra = {}) => ({ run, ...(CWD ? { cwd: CWD } : {}), ...extra })

  test(tag('handshake reports the agent identity'), async (t) => {
    await withBox({}, async (box) => {
      t.is(box.hello.agent, 'bw-agent/1')
      t.is(box.hello.platform, 'linux')
      t.ok(box.hello.cwd.length > 0, 'agent reports a cwd: ' + box.hello.cwd)
      t.alike(box.hello.strayFds, [], 'no descriptors leaked into the sandbox')
    })
  })

  test(tag('ping proves liveness with a matched nonce'), async (t) => {
    await withBox({}, async (box) => {
      t.ok(await box.ping(4242))
    })
  })

  test(tag('a step streams output and propagates its exit code'), async (t) => {
    await withBox({}, async (box) => {
      const run = box.exec(step('echo hello; echo oops >&2; exit 7'))
      const read = collect(run)
      const res = await run.wait()
      const { out, err } = read()

      t.is(res.code, 7, 'exit code survives the wire')
      t.is(out.trim(), 'hello')
      t.is(err.trim(), 'oops', 'stderr stayed separate from stdout')
      t.is(res.error, null)
      t.absent(res.cancelled)
      t.absent(res.truncated)
      t.ok(res.bytesOut > 0)
    })
  })

  test(tag('prepare once, exec many'), async (t) => {
    await withBox({}, async (box) => {
      const outs = []
      for (let i = 0; i < 3; i++) {
        const run = box.exec(step(`echo step-${i}`))
        const read = collect(run)
        const res = await run.wait()
        t.is(res.code, 0, `step ${i} succeeded`)
        outs.push(read().out.trim())
      }
      t.alike(outs, ['step-0', 'step-1', 'step-2'], 'three steps, one sandbox')
    })
  })

  test(tag('step env is an allowlist'), async (t) => {
    await withBox({}, async (box) => {
      const run = box.exec(
        step('echo "MINE=$MINE"; echo "HOME=$HOME"; echo "USER=[$USER]"', { env: { MINE: 'yes' } })
      )
      const read = collect(run)
      await run.wait()
      const { out } = read()
      t.ok(out.includes('MINE=yes'), 'declared env arrives')
      t.ok(out.includes('HOME=/w/home'), 'BASE_ENV floor applied')
      t.ok(out.includes('USER=[]'), 'undeclared host vars absent')
    })
  })

  test(tag('a step can be fed on stdin'), async (t) => {
    await withBox({}, async (box) => {
      const run = box.exec(step('cat'))
      const read = collect(run)
      run.write(Buffer.from('piped-input'))
      run.end()
      const res = await run.wait()
      t.is(res.code, 0)
      t.is(read().out.trim(), 'piped-input')
    })
  })

  test(tag('the driver-side timeout kills a hung step'), async (t) => {
    await withBox({}, async (box) => {
      const run = box.exec(step('sleep 60; echo NOPE'), { timeoutMs: 1000 })
      const read = collect(run)
      const res = await run.wait()
      t.absent(read().out.includes('NOPE'), 'the step did not finish')
      t.ok(res.timedOut, 'reported as a timeout, not a plain failure')
      t.is(res.cancelReason, 'timeout')
    })
  })

  test(tag('cancellation is distinguishable from failure'), async (t) => {
    await withBox({}, async (box) => {
      const run = box.exec(step('sleep 60'))
      setTimeout(() => run.cancel('user'), 300)
      const res = await run.wait()
      t.ok(res.cancelled)
      t.is(res.cancelReason, 'user')
      t.absent(res.timedOut, 'a user cancel is not a timeout')
    })
  })

  test(tag('detached grandchildren are killed with the step'), async (t) => {
    // A build that backgrounds a worker must not leave it running once the step is reported done.
    // The agent signals the process GROUP, so the whole tree goes. Checked from inside, because on
    // an isolated tier the host cannot see the marker file.
    await withBox({}, async (box) => {
      const marker = '/tmp/bw-groupkill-marker'
      const run = box.exec(step(`( sleep 3; echo leaked > ${marker} ) & echo spawned; sleep 60`), {
        timeoutMs: 700
      })
      const read = collect(run)
      const res = await run.wait()
      t.ok(read().out.includes('spawned'))
      t.ok(res.cancelled)

      // Wait past when the grandchild would have written, then look for it in a fresh step.
      await new Promise((resolve) => setTimeout(resolve, 4500))
      const probe = box.exec(step(`test -f ${marker} && echo LEAKED || echo clean`))
      const probeRead = collect(probe)
      await probe.wait()
      t.is(probeRead().out.trim(), 'clean', 'the backgrounded grandchild died with its group')
    })
  })

  test(tag('a log flood is capped and reported as truncated'), async (t) => {
    await withBox({ logBytes: 4096 }, async (box) => {
      const run = box.exec(
        step('for i in $(seq 1 20000); do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done')
      )
      let event = null
      run.on('truncated', (info) => {
        event = info
      })
      const read = collect(run)
      const res = await run.wait()

      t.ok(res.truncated, 'flagged rather than silently dropped')
      t.ok(event, 'emitted a truncated event')
      t.is(res.cancelReason, 'log-limit', 'the step was stopped, not just clipped')
      t.ok(res.bytesOut < 4096 * 200, `output bounded (${res.bytesOut} bytes)`)
      t.ok(read().out.length > 0, 'what did arrive is still delivered')
    })
  })

  test(tag('a missing working directory is reported as such'), async (t) => {
    await withBox({}, async (box) => {
      const run = box.exec({ run: 'true', cwd: '/definitely/not/here' })
      const res = await run.wait()
      t.is(res.code, -1)
      t.ok(
        /working directory does not exist/.test(res.error || ''),
        'error names the cwd: ' + res.error
      )
    })
  })

  test(tag('dispose settles in-flight steps'), async (t) => {
    // wait() must never hang: a caller awaiting a step through a dispose has to get control back.
    const launcher = make()
    const box = sandbox({ launcher })
    await box.prepare()
    const run = box.exec(step('sleep 60'))
    const settled = run.wait()
    await box.dispose()
    const res = await settled
    t.ok(res.cancelled || res.code !== 0, 'the step did not survive the sandbox')
  })

  test(tag('dispose is idempotent'), async (t) => {
    const box = sandbox({ launcher: make() })
    await box.prepare()
    await box.dispose()
    await t.execution(box.dispose(), 'a second dispose is safe')
  })

  // --- properties that only mean something on a real sandbox --------------------------
  if (descriptor.isolated) {
    test(tag('the workspace exists and is writable'), async (t) => {
      // The agent creates /w/{src,home,artifacts} at startup, because the workspace tmpfs arrives
      // empty regardless of what the image built.
      await withBox({}, async (box) => {
        const run = box.exec(
          step(
            'pwd; touch /w/src/probe && echo writable; test -d /w/home && echo home-ok; test -d /w/artifacts && echo artifacts-ok'
          )
        )
        const read = collect(run)
        const res = await run.wait()
        const { out } = read()
        t.is(res.code, 0, 'workspace usable\n' + read().err)
        t.ok(out.includes('/w/src'), 'default cwd is the workspace')
        t.ok(out.includes('writable'))
        t.ok(out.includes('home-ok'))
        t.ok(out.includes('artifacts-ok'))
      })
    })

    test(tag('the step runs at the expected uid'), async (t) => {
      await withBox({}, async (box) => {
        const run = box.exec(step('id -u'))
        const read = collect(run)
        await run.wait()
        t.is(read().out.trim(), descriptor.expectUid, `uid for the ${name} tier`)
      })
    })

    test(tag('a directory can be streamed in and out'), async (t) => {
      // The only way data crosses the boundary: there are no host mounts, by design and by kernel
      // restriction. Verified on the real tiers because the transfer path is where a malicious
      // archive would act, and lib/transfer.js is only useful if it is actually on that path.
      const fs = require('bare-fs')
      const stamp = Date.now()
      const src = `/tmp/bw-life-put-${stamp}`
      const out = `/tmp/bw-life-get-${stamp}`
      fs.mkdirSync(src + '/nested', { recursive: true })
      fs.writeFileSync(src + '/a.txt', 'from the host')
      fs.writeFileSync(src + '/nested/b.bin', Buffer.from([0, 1, 2, 255]))

      try {
        await withBox({}, async (box) => {
          const put = await box.put(src, '/w/src/incoming')
          t.is(put.files, 2, 'both files arrived')

          const check = box.exec(
            step('cat /w/src/incoming/a.txt; wc -c < /w/src/incoming/nested/b.bin')
          )
          const read = collect(check)
          const res = await check.wait()
          t.is(res.code, 0, 'the sandbox can read what we sent\n' + read().err)
          t.ok(read().out.includes('from the host'), 'text content intact')
          t.ok(read().out.includes('4'), 'binary length intact')

          const produce = box.exec(
            step('mkdir -p /w/artifacts/out && echo made-inside > /w/artifacts/out/result.txt')
          )
          produce.stdout.on('data', () => {})
          t.is((await produce.wait()).code, 0, 'produced an artifact')

          const got = await box.get('/w/artifacts/out', out)
          t.is(got.files, 1, 'one file came back')
          t.is(
            fs.readFileSync(out + '/result.txt', 'utf8').trim(),
            'made-inside',
            'and its bytes survived'
          )
        })
      } finally {
        for (const d of [src, out]) {
          try {
            fs.rmSync(d, { recursive: true, force: true })
          } catch {}
        }
      }
    })

    test(tag('an executable survives the round trip in both directions'), async (t) => {
      // A regression test for a real, silent failure: the agent shares lib/transfer.js, and while
      // that file wrote every extracted file 0644 an executable sent INTO a sandbox arrived
      // non-executable. Nothing failed -- the build succeeded, the artifact came back, and the
      // release folder shipped binaries nobody could run. It also means a stale baked agent
      // reintroduces the bug invisibly, so this asserts on the real tiers rather than in a unit test.
      const fs = require('bare-fs')
      const stamp = Date.now()
      const src = `/tmp/bw-life-exe-in-${stamp}`
      const out = `/tmp/bw-life-exe-out-${stamp}`
      fs.mkdirSync(src, { recursive: true })
      fs.writeFileSync(src + '/tool', '#!/bin/sh\necho ran\n', { mode: 0o755 })
      fs.writeFileSync(src + '/data', 'not executable\n', { mode: 0o644 })

      try {
        await withBox({}, async (box) => {
          await box.put(src, '/w/src/bin')

          // Asserted from inside with `test -x`, not by reading a mode we wrote ourselves.
          const check = box.exec(
            step(
              'test -x /w/src/bin/tool && echo TOOL-EXEC; test -x /w/src/bin/data || echo DATA-PLAIN; /w/src/bin/tool'
            )
          )
          const read = collect(check)
          const res = await check.wait()
          t.is(res.code, 0, 'the sandbox could run what we sent\n' + read().err)
          t.ok(read().out.includes('TOOL-EXEC'), 'the executable arrived executable')
          t.ok(read().out.includes('DATA-PLAIN'), 'and a data file did not become one')
          t.ok(read().out.includes('ran'), 'and it actually executes')

          const produce = box.exec(
            step(
              'mkdir -p /w/artifacts/b && printf "#!/bin/sh\\n" > /w/artifacts/b/made && chmod +x /w/artifacts/b/made && echo plain > /w/artifacts/b/notes'
            )
          )
          produce.stdout.on('data', () => {})
          t.is((await produce.wait()).code, 0, 'produced an executable inside')

          await box.get('/w/artifacts/b', out)
          t.ok(fs.statSync(out + '/made').mode & 0o100, 'and it is still executable on the host')
          t.absent(fs.statSync(out + '/notes').mode & 0o111, 'while a plain file stays plain')
        })
      } finally {
        for (const d of [src, out]) {
          try {
            fs.rmSync(d, { recursive: true, force: true })
          } catch {}
        }
      }
    })

    test(tag('a symlink produced in the sandbox is not followed on the way out'), async (t) => {
      // A build could otherwise plant a link and have the runner copy out anything the sandbox
      // could read.
      const fs = require('bare-fs')
      const out = `/tmp/bw-life-link-${Date.now()}`
      try {
        await withBox({}, async (box) => {
          const setup = box.exec(
            step(
              'mkdir -p /w/artifacts/x && echo real > /w/artifacts/x/real.txt && ln -s /etc/hostname /w/artifacts/x/leak'
            )
          )
          setup.stdout.on('data', () => {})
          t.is((await setup.wait()).code, 0)

          const got = await box.get('/w/artifacts/x', out)
          t.is(got.files, 1, 'only the real file was packed')
          t.alike(fs.readdirSync(out), ['real.txt'], 'the symlink did not come out')
        })
      } finally {
        try {
          fs.rmSync(out, { recursive: true, force: true })
        } catch {}
      }
    })

    test(tag('the step has no network'), async (t) => {
      // Cheap end-to-end confirmation that the posture the escape suite proves is the same posture
      // a step actually runs under -- not a separately-configured container.
      await withBox({}, async (box) => {
        const run = box.exec(
          step(
            'awk \'NR>1 && $2=="00000000" {n++} END {print "defaultroutes=" n+0}\' /proc/net/route'
          )
        )
        const read = collect(run)
        await run.wait()
        t.is(read().out.trim(), 'defaultroutes=0', 'no egress path from a step')
      })
    })
  }
}

module.exports = { lifecycleSuite, collect }
