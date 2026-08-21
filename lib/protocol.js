'use strict'

// The agent wire protocol.
//
// Thin layer over the generated hrpc client in schema/spec/hrpc. Everything interesting about the
// protocol lives in schema/builder/{types,rpc}.js; this file exists so the rest of the codebase
// imports one stable module instead of reaching into generated output, and so the frame-kind
// constants have exactly one definition.
//
// Why a long-lived stream instead of `podman exec`: crun's krun handler has no exec at all, so a
// microVM sandbox cannot be re-entered. That constraint turns out to be a gift -- the same duplex
// works for a local subprocess, a container, a microVM, and (later) a remote peer over hyperdht,
// so remote dispatch becomes a transport swap rather than a rewrite.
//
// Transport shape: fd 0 in, fd 1 out, fd 2 reserved for agent diagnostics. That is all `podman
// run -i` gives us, and test/fidelity.js proved it is byte-exact and backpressured under the
// hardened flag set.

const { Duplex } = require('bare-stream')
const HRPC = require('../schema/spec/hrpc')
const { EXEC_IN, EXEC_OUT } = require('../schema/builder/types.js')

const PROTOCOL_VERSION = 1

// Terminal frames end an exec stream; anything else is more output to come.
const TERMINAL = new Set([EXEC_OUT.EXIT, EXEC_OUT.ERROR])

function isTerminal(kind) {
  return TERMINAL.has(kind)
}

// Stitch a read-only stream and a write-only stream into one byte duplex.
//
// Do NOT use `Duplex.from({ readable, writable })` for this: it yields an OBJECT-mode stream, so
// chunks arrive as plain objects and the framing layer underneath hrpc fails with
// "buffer.subarray is not a function". Found the hard way. This bridge stays in byte mode and
// forwards backpressure in both directions.
class Bridge extends Duplex {
  constructor(readable, writable) {
    super()
    this._r = readable
    this._w = writable

    readable.on('data', (chunk) => {
      if (!this.push(chunk)) readable.pause()
    })
    readable.on('end', () => this.push(null))
    readable.on('error', (err) => this.destroy(err))
    writable.on('error', (err) => this.destroy(err))
  }

  // bare-stream follows the NODE stream conventions -- _read(size), _write(chunk, encoding, cb),
  // _destroy(err, cb) -- not streamx's _read(cb)/_write(data, cb). Getting this wrong presents as
  // "cb is not a function" from inside the stream machinery.
  _read() {
    this._r.resume()
  }

  _write(chunk, encoding, cb) {
    if (this._w.write(chunk)) return cb(null)
    this._w.once('drain', () => cb(null))
  }

  _final(cb) {
    try {
      this._w.end()
    } catch {}
    cb(null)
  }

  _destroy(err, cb) {
    try {
      this._r.destroy()
    } catch {}
    try {
      this._w.destroy()
    } catch {}
    cb(err || null)
  }
}

function bridge(readable, writable) {
  return new Bridge(readable, writable)
}

// Build a duplex from a read fd and a write fd. A subprocess's stdin is read-only and its stdout
// write-only, so the two halves have to be stitched together rather than opened as one handle.
function duplexFromFds(readFd = 0, writeFd = 1) {
  const Pipe = require('bare-pipe')
  return bridge(new Pipe(readFd), new Pipe(writeFd))
}

function createRPC(stream) {
  return new HRPC(stream)
}

// Frame constructors. Small, but they keep `kind` and its payload fields from drifting apart at
// the ~dozen call sites that build frames.
const frames = {
  start({ run, shell = 'bash', cwd = '/w/src', env = [], timeoutMs = 0 }) {
    return { kind: EXEC_IN.START, run, shell, cwd, env, timeoutMs }
  },
  stdin(chunk) {
    return { kind: EXEC_IN.STDIN, chunk }
  },
  eof() {
    return { kind: EXEC_IN.EOF }
  },
  signal(signal) {
    return { kind: EXEC_IN.SIGNAL, signal }
  },
  stdout(chunk) {
    return { kind: EXEC_OUT.STDOUT, chunk }
  },
  stderr(chunk) {
    return { kind: EXEC_OUT.STDERR, chunk }
  },
  exit({ code = 0, signal = '', timedOut = false }) {
    return { kind: EXEC_OUT.EXIT, code, signal, timedOut }
  },
  error(message) {
    return { kind: EXEC_OUT.ERROR, message }
  }
}

module.exports = {
  HRPC,
  createRPC,
  bridge,
  Bridge,
  duplexFromFds,
  frames,
  isTerminal,
  EXEC_IN,
  EXEC_OUT,
  PROTOCOL_VERSION
}
