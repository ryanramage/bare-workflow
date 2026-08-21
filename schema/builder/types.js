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
      { name: 'cwd', type: 'string', required: true }
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
      { name: 'timedOut', type: 'bool' }
    ]
  })
}

module.exports.EXEC_IN = EXEC_IN
module.exports.EXEC_OUT = EXEC_OUT
