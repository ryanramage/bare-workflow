'use strict'

// Standalone entry point for the agent binary.
//
// Separate from index.js because `require.main === module` does NOT hold inside a bare-build
// standalone bundle: the guard silently never fires, the agent never starts serving, and the
// driver just times out on the handshake with no clue why. So the executable gets an entry that
// serves unconditionally, and index.js stays a plain library that tests can require without
// grabbing fd 0/1.
//
// Built by scripts/build/agent.sh into out/agent/bw-agent and baked into the sandbox image at
// /opt/bw/agent -- there is no bind mount available to inject it later.

const protocol = require('../protocol.js')
const { serve, ensureWorkspace } = require('./index.js')

// /w is a tmpfs and therefore empty on every start, so the subtree has to be created here rather
// than in the image. Do it before serving, so the first exec cannot race it.
ensureWorkspace(require('bare-env').BW_WORKSPACE || '/w')

serve(protocol.duplexFromFds(0, 1))

// Keep the process alive: the only thing holding it open is the stdio duplex, and Bare will exit
// if it decides there is nothing left to do.
if (typeof Bare !== 'undefined' && Bare.on) {
  Bare.on('beforeExit', () => {})
}
