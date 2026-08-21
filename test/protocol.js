'use strict'

// Protocol-level tests. In-memory duplexPair, no subprocess, no container -- these run in
// milliseconds and cover the framing contract itself.

const test = require('brittle')
const { duplexPair } = require('bare-stream')
const protocol = require('../lib/protocol.js')

const { EXEC_IN, EXEC_OUT, frames } = protocol

test('frame constructors tag every kind', (t) => {
  t.is(frames.start({ run: 'x' }).kind, EXEC_IN.START)
  t.is(frames.stdin(Buffer.from('a')).kind, EXEC_IN.STDIN)
  t.is(frames.eof().kind, EXEC_IN.EOF)
  t.is(frames.signal('SIGTERM').kind, EXEC_IN.SIGNAL)
  t.is(frames.stdout(Buffer.from('a')).kind, EXEC_OUT.STDOUT)
  t.is(frames.stderr(Buffer.from('a')).kind, EXEC_OUT.STDERR)
  t.is(frames.exit({ code: 2 }).kind, EXEC_OUT.EXIT)
  t.is(frames.error('boom').kind, EXEC_OUT.ERROR)
})

test('start frame carries defaults, not undefined', (t) => {
  const f = frames.start({ run: 'npm ci' })
  t.is(f.run, 'npm ci')
  t.is(f.shell, 'bash')
  t.is(f.cwd, '/w/src')
  t.alike(f.env, [])
  t.is(f.timeoutMs, 0)
})

test('only exit and error are terminal', (t) => {
  t.ok(protocol.isTerminal(EXEC_OUT.EXIT))
  t.ok(protocol.isTerminal(EXEC_OUT.ERROR))
  t.absent(protocol.isTerminal(EXEC_OUT.STDOUT))
  t.absent(protocol.isTerminal(EXEC_OUT.STDERR))
})

test('hello and ping round-trip over hrpc', async (t) => {
  const [left, right] = duplexPair()
  const server = protocol.createRPC(right)
  const client = protocol.createRPC(left)

  server.onHello((req) => ({
    agent: 'test',
    platform: 'linux',
    arch: 'x64',
    pid: 7,
    strayFds: [],
    cwd: '/w'
  }))
  server.onPing((req) => ({ nonce: req.nonce }))

  const hello = await client.hello({ driver: 'unit' })
  t.is(hello.agent, 'test')
  t.is(hello.pid, 7)
  t.alike(hello.strayFds, [])

  const pong = await client.ping({ nonce: 99 })
  t.is(pong.nonce, 99, 'nonce echoes, so the response is matched to the request')
})

test('exec duplex keeps stdout and stderr distinct end to end', async (t) => {
  const [left, right] = duplexPair()
  const server = protocol.createRPC(right)
  const client = protocol.createRPC(left)

  server.onExec((stream) => {
    stream.on('data', (frame) => {
      if (frame.kind !== EXEC_IN.START) return
      stream.write(frames.stdout(Buffer.from('to-stdout')))
      stream.write(frames.stderr(Buffer.from('to-stderr')))
      stream.write(frames.exit({ code: 0 }))
      stream.end()
    })
  })

  const dx = client.exec()
  const got = []
  dx.on('data', (f) => got.push([f.kind, f.chunk ? f.chunk.toString() : null, f.code]))
  dx.write(frames.start({ run: 'anything' }))
  await new Promise((resolve) => dx.on('end', resolve))

  t.alike(got, [
    [EXEC_OUT.STDOUT, 'to-stdout', 0],
    [EXEC_OUT.STDERR, 'to-stderr', 0],
    [EXEC_OUT.EXIT, null, 0]
  ])
})

test('buffers survive the wire as buffers', async (t) => {
  // Regression guard. An earlier transport used Duplex.from({readable,writable}), which yields an
  // OBJECT-mode stream: chunks arrived as plain objects and the framing layer died with
  // "buffer.subarray is not a function". Every byte value must round-trip intact.
  const [left, right] = duplexPair()
  const server = protocol.createRPC(right)
  const client = protocol.createRPC(left)

  const payload = Buffer.alloc(256)
  for (let i = 0; i < 256; i++) payload[i] = i

  server.onExec((stream) => {
    stream.on('data', (frame) => {
      if (frame.kind === EXEC_IN.STDIN) {
        stream.write(frames.stdout(frame.chunk)) // echo it straight back
        stream.write(frames.exit({ code: 0 }))
        stream.end()
      }
    })
  })

  const dx = client.exec()
  const chunks = []
  dx.on('data', (f) => {
    if (f.kind === EXEC_OUT.STDOUT) chunks.push(f.chunk)
  })
  dx.write(frames.stdin(payload))
  await new Promise((resolve) => dx.on('end', resolve))

  const echoed = Buffer.concat(chunks)
  t.is(echoed.byteLength, 256, 'all 256 byte values returned')
  t.ok(Buffer.isBuffer(echoed), 'still a Buffer, not an object')
  t.alike(echoed, payload, 'byte-exact round trip')
})

test('bridge is byte mode, not object mode', async (t) => {
  const { PassThrough } = require('bare-stream')
  const up = new PassThrough()
  const down = new PassThrough()
  const b = protocol.bridge(up, down)

  const seen = []
  b.on('data', (c) => seen.push(c))
  up.write(Buffer.from([0xde, 0xad]))
  await new Promise((resolve) => setTimeout(resolve, 20))

  t.is(seen.length, 1)
  t.ok(Buffer.isBuffer(seen[0]) || seen[0] instanceof Uint8Array, 'chunk is bytes')
  t.is(typeof seen[0].subarray, 'function', 'has subarray -- the framing layer needs it')
})
