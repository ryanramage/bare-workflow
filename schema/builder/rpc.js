'use strict'

// hrpc command definitions.
//
// hrpc is APPEND-ONLY: redefining a command with different schemas or stream types throws at build
// time. That is a feature for us -- the wire contract between a driver and an agent baked into an
// older image cannot drift silently. It also means we register only what we implement today and
// append `put`/`get` when the transfer layer lands, rather than reserving speculative commands.

module.exports = function generateRPC(hrpc) {
  const ns = hrpc.namespace('bw')

  ns.register({
    name: 'hello',
    request: { name: '@bw/hello-request', stream: false },
    response: { name: '@bw/hello-response', stream: false }
  })

  ns.register({
    name: 'ping',
    request: { name: '@bw/ping-request', stream: false },
    response: { name: '@bw/ping-response', stream: false }
  })

  // One duplex per step: independent lifetimes, independent cancellation, and stdout/stderr stay
  // separated all the way to the driver instead of being merged into one log blob.
  ns.register({
    name: 'exec',
    request: { name: '@bw/exec-request', stream: true },
    response: { name: '@bw/exec-response', stream: true }
  })

  // Transfer. Appended rather than reserved up front, which is exactly what hrpc's append-only
  // guarantee is for: an agent baked into an older image simply does not answer these, instead of
  // silently disagreeing about what they mean.
  ns.register({
    name: 'put',
    request: { name: '@bw/put-request', stream: true },
    response: { name: '@bw/put-response', stream: false }
  })

  ns.register({
    name: 'get',
    request: { name: '@bw/get-request', stream: false },
    response: { name: '@bw/get-response', stream: true }
  })
}
