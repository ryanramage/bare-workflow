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
  // Where the agent actually executes for this launcher -- see the handshake test below.
  const expectPlatform = descriptor.expectPlatform || 'linux'
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

      // Not hardcoded 'linux'. Every ISOLATED tier runs a Linux guest whatever the host is -- that
      // is the point of TIER_PLATFORM -- but the test-only local launcher runs the agent as a host
      // process, so on a Mac it reports darwin. Asserting 'linux' for all three made the local
      // launcher fail on macOS for a reason that had nothing to do with the protocol.
      t.is(box.hello.platform, expectPlatform, `${name} runs the agent on ${expectPlatform}`)
      t.ok(box.hello.cwd.length > 0, 'agent reports a cwd: ' + box.hello.cwd)

      // An empty strayFds list means nothing unless the scan actually ran -- on a platform with no
      // procfs the old code returned [] and this assertion passed while measuring nothing.
      if (descriptor.isolated) {
        // An isolated tier is a Linux guest, which always has /proc. "Cannot scan" here is a real
        // failure, not an environment quirk, so it is asserted rather than skipped.
        t.is(box.fdScan, 'ok', 'the fd-leak detector actually ran')
        t.alike(box.hello.strayFds, [], 'no descriptors leaked into the sandbox')
      } else if (box.fdScan === 'ok') {
        t.alike(box.hello.strayFds, [], 'no descriptors leaked into the sandbox')
      } else {
        t.comment(`fd-leak detection is inert for the ${name} launcher: ${box.fdScan}`)
      }
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
      // Derived from the sandbox's workspace, not the literal `/w`: a native tier's workspace is a
      // per-job scratch directory on the host, so pinning the string here would assert a container
      // detail rather than the property, which is that the env floor is applied at all.
      t.ok(out.includes(`HOME=${box.workspace}/home`), 'base env floor applied')
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
        // Built from box.workspace, not the literal `/w`. Every container tier answers `/w`, but a
        // native tier's workspace is a per-job scratch directory on the host -- pinning the string
        // would assert a container detail rather than the property, which is that the agent creates
        // its subtree wherever the launcher put it.
        const w = box.workspace
        const run = box.exec(
          step(
            `pwd; touch ${w}/src/probe && echo writable; test -d ${w}/home && echo home-ok; test -d ${w}/artifacts && echo artifacts-ok`
          )
        )
        const read = collect(run)
        const res = await run.wait()
        const { out } = read()
        t.is(res.code, 0, 'workspace usable\n' + read().err)
        t.ok(out.includes(w + '/src'), 'default cwd is the workspace')
        t.ok(out.includes('writable'))
        t.ok(out.includes('home-ok'))
        t.ok(out.includes('artifacts-ok'))
      })
    })

    test(tag('the step runs at the expected uid'), async (t) => {
      // Not every isolated tier maps a uid. The container tiers do (1000, or 0 under krun where the
      // VM is the boundary); the native seatbelt tier cannot, because macOS has no user namespaces
      // -- a step runs as the developer, and that is recorded as an unenforceable limit rather than
      // dressed up as isolation. A descriptor with no expectUid says so instead of asserting a value
      // invented to make the test pass.
      if (!descriptor.expectUid) {
        t.comment(`the ${name} tier does not map a uid -- there is nothing to assert`)
        return t.pass('skipped')
      }
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
          const put = await box.put(src, box.workspace + '/src/incoming')
          t.is(put.files, 2, 'both files arrived')

          const check = box.exec(
            step(
              `cat ${box.workspace}/src/incoming/a.txt; wc -c < ${box.workspace}/src/incoming/nested/b.bin`
            )
          )
          const read = collect(check)
          const res = await check.wait()
          t.is(res.code, 0, 'the sandbox can read what we sent\n' + read().err)
          t.ok(read().out.includes('from the host'), 'text content intact')
          t.ok(read().out.includes('4'), 'binary length intact')

          const produce = box.exec(
            step(
              `mkdir -p ${box.workspace}/artifacts/out && echo made-inside > ${box.workspace}/artifacts/out/result.txt`
            )
          )
          produce.stdout.on('data', () => {})
          t.is((await produce.wait()).code, 0, 'produced an artifact')

          const got = await box.get(`${box.workspace}/artifacts/out`, out)
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
          await box.put(src, `${box.workspace}/src/bin`)

          // Asserted from inside with `test -x`, not by reading a mode we wrote ourselves.
          const check = box.exec(
            step(
              `test -x ${box.workspace}/src/bin/tool && echo TOOL-EXEC; test -x ${box.workspace}/src/bin/data || echo DATA-PLAIN; ${box.workspace}/src/bin/tool`
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
              `mkdir -p ${box.workspace}/artifacts/b && printf "#!/bin/sh\\n" > ${box.workspace}/artifacts/b/made && chmod +x ${box.workspace}/artifacts/b/made && echo plain > ${box.workspace}/artifacts/b/notes`
            )
          )
          produce.stdout.on('data', () => {})
          t.is((await produce.wait()).code, 0, 'produced an executable inside')

          await box.get(`${box.workspace}/artifacts/b`, out)
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
              `mkdir -p ${box.workspace}/artifacts/x && echo real > ${box.workspace}/artifacts/x/real.txt && ln -s /etc/hostname ${box.workspace}/artifacts/x/leak`
            )
          )
          setup.stdout.on('data', () => {})
          t.is((await setup.wait()).code, 0)

          const got = await box.get(`${box.workspace}/artifacts/x`, out)
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
        // Two probes, because the Linux one cannot run on darwin and skipping would leave the
        // strongest claim this suite makes untested on the tier that needs it most.
        //
        // Linux: count default routes in /proc/net/route -- kernel-provided, always present. NOT
        // `ip route`, which is absent from ubuntu:24.04 and made an earlier version of this pass
        // vacuously in BOTH postures until the negative control caught it.
        //
        // darwin: there is no /proc, and a native step shares the host's routing table, so counting
        // routes would report the developer's own network and fail. What the Seatbelt profile
        // actually denies is the socket, so the probe is to ATTEMPT a connection and require it to
        // fail. That is a stronger check than the Linux one, not a weaker substitute.
        const linux = box.hello.platform === 'linux'
        const run = box.exec(
          step(
            linux
              ? 'awk \'NR>1 && $2=="00000000" {n++} END {print "egress=" n+0}\' /proc/net/route'
              : 'if exec 3<>/dev/tcp/1.1.1.1/443 2>/dev/null; then echo egress=1; else echo egress=0; fi'
          )
        )
        const read = collect(run)
        await run.wait()
        t.is(read().out.trim(), 'egress=0', `no egress path from a step (${box.hello.platform})`)
      })
    })
  }
}

module.exports = { lifecycleSuite, collect }
