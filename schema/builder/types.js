'use strict'

// Hyperschema types for the agent protocol.
//
// The protocol crosses the trust boundary: the driver is trusted, the agent's peer (the workload)
// is not. Two consequences shape every message here:
//
//   * Step commands travel as DATA, never as host argv. The agent picks the shell inside the
//     sandbox, so no host-side quoting bug can become host command injection.
//   * A duplex stream carries a tagged union, because hrpc gives one request type and one
//     response type per streaming command. The `kind` field is that tag.

// Frame kinds on the exec request stream (driver -> agent).
const EXEC_IN = {
  START: 0, // begin the step; carries run/shell/cwd/env/timeout
  STDIN: 1, // a chunk for the step's stdin
  EOF: 2, // no more stdin
  SIGNAL: 3 // deliver a signal to the step's process group
}

// Frame kinds on the exec response stream (agent -> driver).
const EXEC_OUT = {
  STDOUT: 0,
  STDERR: 1,
  EXIT: 2, // terminal: carries code/signal
  ERROR: 3 // terminal: the agent could not run the step at all
}

module.exports = function generateTypes(schema) {
  const ns = schema.namespace('bw')

  // --- handshake ---------------------------------------------------------------------
  ns.register({
    name: 'hello-request',
    fields: [{ name: 'driver', type: 'string', required: true }]
  })

  ns.register({
    name: 'hello-response',
    fields: [
      { name: 'agent', type: 'string', required: true },
      { name: 'platform', type: 'string', required: true },
      { name: 'arch', type: 'string', required: true },
      { name: 'pid', type: 'uint', required: true },
      // The agent enumerates /proc/self/fd on startup and reports anything beyond 0/1/2. A
      // non-empty list means a descriptor leaked in and the driver aborts the job rather than
      // running a workload next to an inherited handle.
      { name: 'strayFds', type: 'string', array: true },
      { name: 'cwd', type: 'string', required: true },
      // Which commands this agent actually implements.
      //
      // hrpc's append-only guarantee protects the ENCODING -- it does not stop a driver calling a
      // command that an older agent has no handler for, and the failure is not graceful: the agent
      // dies with "this._handlers[command] is not a function" and the driver sees only a crashed
      // container. In a farm where peers run different image versions, that is a routine situation,
      // so agents advertise their surface and the driver checks before it calls.
      { name: 'commands', type: 'string', array: true },
      // Whether the fd scan above could actually RUN, as distinct from what it found.
      //
      // strayFds enumerates /proc/self/fd. Where there is no procfs the old code caught the error
      // and returned an empty list, so "I looked and found nothing" and "I could not look" were the
      // same value on the wire -- a security control reporting clean while measuring nothing. That
      // is exactly what decision 4 exists to forbid, and it is invisible on Linux, which is why it
      // survived. 'ok' means the scan ran; anything else is the reason it did not.
      { name: 'fdScan', type: 'string' }
    ]
  })

  // --- liveness ----------------------------------------------------------------------
  ns.register({
    name: 'ping-request',
    fields: [{ name: 'nonce', type: 'uint', required: true }]
  })

  ns.register({
    name: 'ping-response',
    fields: [{ name: 'nonce', type: 'uint', required: true }]
  })

  // --- step execution ----------------------------------------------------------------
  ns.register({
    name: 'exec-request',
    fields: [
      { name: 'kind', type: 'uint', required: true },
      // START
      { name: 'run', type: 'string' },
      { name: 'shell', type: 'string' },
      { name: 'cwd', type: 'string' },
      // Flat KEY=VALUE pairs; the agent never merges these with its own environment.
      { name: 'env', type: 'string', array: true },
      { name: 'timeoutMs', type: 'uint' },
      // STDIN
      { name: 'chunk', type: 'buffer' },
      // SIGNAL
      { name: 'signal', type: 'string' }
    ]
  })

  ns.register({
    name: 'exec-response',
    fields: [
      { name: 'kind', type: 'uint', required: true },
      { name: 'chunk', type: 'buffer' },
      { name: 'code', type: 'int' },
      { name: 'signal', type: 'string' },
      { name: 'message', type: 'string' },
      // Set on EXIT when the agent stopped the step itself, so the driver can distinguish
      // "the build failed" from "we killed it".
      { name: 'timedOut', type: 'bool' },
      // Raw contents of the step's output file, shipped verbatim on EXIT.
      //
      // The agent does NOT parse it. This content is attacker-controlled -- a build can write
      // whatever it likes -- so it is parsed once, on the trusted side, by the shared parser in
      // lib/protocol.js. One tested parser beats two, and the driver is where outputs get used.
      { name: 'outputsRaw', type: 'string' },
      // True when the agent stopped reading because the file exceeded its cap.
      { name: 'outputsTruncated', type: 'bool' }
    ]
  })

  // --- file transfer -----------------------------------------------------------------
  //
  // Data crosses the boundary as a TAR STREAM, not a shared mount. Rootless idmapped bind mounts
  // are kernel-forbidden, and refusing host mounts altogether removes the whole bind-mount attack
  // surface plus the host-path-rebasing problem that comes with it. The cost is copying bytes; the
  // benefit is that no host path ever exists inside the sandbox.

  ns.register({
    name: 'put-request',
    fields: [
      { name: 'kind', type: 'uint', required: true },
      // START
      { name: 'path', type: 'string' },
      // CHUNK: raw tar bytes
      { name: 'chunk', type: 'buffer' }
    ]
  })

  ns.register({
    name: 'put-response',
    fields: [
      { name: 'ok', type: 'bool' },
      { name: 'files', type: 'uint' },
      { name: 'bytes', type: 'uint' },
      { name: 'message', type: 'string' }
    ]
  })

  ns.register({
    name: 'get-request',
    fields: [
      { name: 'path', type: 'string', required: true },
      // Glob patterns relative to `path`; empty means everything under it.
      { name: 'globs', type: 'string', array: true }
    ]
  })

  ns.register({
    name: 'get-response',
    fields: [
      { name: 'kind', type: 'uint', required: true },
      { name: 'chunk', type: 'buffer' },
      { name: 'message', type: 'string' },
      { name: 'files', type: 'uint' },
      { name: 'bytes', type: 'uint' }
    ]
  })
}

// Frame kinds on the put request stream (driver -> agent).
const PUT_IN = {
  START: 0, // begin an extraction at `path`
  CHUNK: 1, // raw tar bytes
  END: 2 // no more bytes
}

// Frame kinds on the get response stream (agent -> driver).
const GET_OUT = {
  CHUNK: 0, // raw tar bytes
  DONE: 1, // terminal: carries counts
  ERROR: 2 // terminal
}

module.exports.PUT_IN = PUT_IN
module.exports.GET_OUT = GET_OUT
module.exports.EXEC_IN = EXEC_IN
module.exports.EXEC_OUT = EXEC_OUT
