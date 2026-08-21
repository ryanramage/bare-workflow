// The project's own tests, run inside the sandbox to prove a real `npm test` works there.
const assert = require('bare-assert')
const pkg = require('../package.json')

assert.ok(pkg.name === 'hello-pear', 'package name is stable')
// bare-build normalizes --name by lowercasing and collapsing non-alphanumerics. If that changed
// pkg.name, the OTA updater would look for a filename that does not exist in the drive.
const identifier = pkg.name
  .replace(/[^a-z0-9]+/gi, '-')
  .replace(/([a-z0-9])([A-Z])/g, '$1-$2')
  .toLowerCase()
assert.ok(identifier === pkg.name, `pkg.name must survive bare-build's normalizer: ${identifier}`)
console.log('ok - hello-pear')
