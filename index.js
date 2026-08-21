'use strict'

// Barrel export.
//
// Grouped by what each part is responsible for rather than alphabetically, because the boundaries
// are the design: `schema` decides what a workflow may say, `isolation` decides what an untrusted
// job may do, and `publish` is the one place that deliberately sits outside both.

module.exports = {
  WorkflowError: require('./lib/errors.js'),

  // YAML -> validated, normalized, frozen Workflow. The only module that touches YAML.
  schema: require('./lib/schema'),
  targets: require('./lib/targets.js'),
  toolchains: require('./lib/toolchains.js'),
  interpolate: require('./lib/interpolate.js'),
  graph: require('./lib/graph.js'),

  // Driver-side sandbox handle: prepare once, exec many, dispose.
  sandbox: require('./lib/sandbox.js'),

  // The agent wire protocol (hrpc over fd 0/1) and its frame constructors.
  protocol: require('./lib/protocol.js'),

  // Validating tar in and out. Never `podman cp`, which resolves symlinks.
  transfer: require('./lib/transfer.js'),

  // Artifacts and cache, written against a DRIVE rather than a path -- localdrive today,
  // hyperdrive when the farm lands, with no change here.
  store: require('./lib/store'),

  attestation: require('./lib/attestation.js'),
  prefetch: require('./lib/prefetch.js'),

  // The trusted side: runner-held secrets, and the drivers allowed to use them. Deliberately
  // separate from everything above, because everything above assumes its input is hostile.
  config: require('./lib/config.js'),
  publish: require('./lib/publish'),

  isolation: {
    podman: {
      // Pure spec -> argv. The security-critical file; snapshot tested.
      argv: require('./lib/isolation/podman/argv.js'),
      seccomp: require('./lib/isolation/podman/seccomp.js'),
      launcher: require('./lib/isolation/podman/launcher.js')
    }
  }
}
