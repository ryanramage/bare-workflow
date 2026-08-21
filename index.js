'use strict'

// Barrel export.
//
// Today this is the isolation layer and the agent protocol -- the parts that have to be right
// before anything else matters. The workflow schema, scheduler, and the P2P farm are not built yet.

module.exports = {
  WorkflowError: require('./lib/errors.js'),

  // Driver-side sandbox handle: prepare once, exec many, dispose.
  sandbox: require('./lib/sandbox.js'),

  // The agent wire protocol (hrpc over fd 0/1) and its frame constructors.
  protocol: require('./lib/protocol.js'),

  isolation: {
    podman: {
      // Pure spec -> argv. The security-critical file; snapshot tested.
      argv: require('./lib/isolation/podman/argv.js'),
      seccomp: require('./lib/isolation/podman/seccomp.js'),
      launcher: require('./lib/isolation/podman/launcher.js')
    }
  }
}
