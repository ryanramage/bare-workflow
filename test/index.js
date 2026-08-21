// Aggregator.
//
// Ordered fast-to-slow: pure unit tests first (milliseconds, no IO), then the tests that launch
// real processes and real sandboxes. Everything container-dependent skips with a stated reason when
// podman or the base image is missing, so this suite stays green on a machine without a container
// runtime -- but it says so rather than quietly testing less.

// Unit -- pure functions, no IO.
require('./schema.js')
require('./targets.js')
require('./toolchains.js')
require('./detect.js')
require('./attestation.js')
require('./interpolate.js')
require('./graph.js')
require('./transfer.js')
require('./store.js')
require('./prefetch.js')
require('./argv.js')
require('./seccomp.js')
require('./protocol.js')
require('./agent.js')

// The Sandbox lifecycle, run against every launcher available: a host subprocess (fast, no
// isolation, test-only), a hardened container, and a krun microVM. Same assertions, three
// transports -- this is what joins "the protocol works" to "the sandbox holds".
require('./lifecycle.js')

// Integration -- the generated argv must actually be accepted by podman.
require('./argv-runs.js')

// End to end -- the real CLI against the example workflows.
require('./cli.js')
require('./hello-pear.js')

// Publishing -- the schema refusals are unit-fast, and the staged flow stands up a real DHT on
// localhost with a throwaway key, so no network and no real release line is involved.
require('./publish.js')

// Security -- the escape suite and its negative control. Read test/escape/index.js before trusting
// any of it: if the negative control stops failing, the rest is measuring nothing.
require('./escape/index.js')
require('./escape/exhaustion.js')
