// Minimal stand-in for hello-pear-bare's entry point.
//
// The app body is deliberately trivial -- what is being exercised is the BUILD shape, so a failure
// is unambiguously the runner's or bare-build's rather than a native addon's.
//
// The one non-obvious thing carried over from the real template is the dev/standalone argv offset.
// A standalone binary has no separate script slot, so slicing 2 unconditionally eats the first real
// argument. Getting this wrong is a genuine bug the template had to fix upstream.

import { command, flag, summary } from 'paparam'
import pkg from './package.json'

const appName = pkg.productName || pkg.name
const isDev =
  Bare.argv[0]
    .split(/[\\/]/)
    .pop()
    .replace(/\.exe$/, '') === 'bare'

const cmd = command(
  appName,
  summary(pkg.description),
  flag('--version|-v', 'Print the current version'),
  () => {
    if (cmd.flags.version) {
      console.log(pkg.version)
      return
    }
    console.log(`hello from ${appName} ${pkg.version}`)
    console.log(`upgrade ${pkg.upgrade}`)
    console.log(`running ${isDev ? 'under the bare CLI' : 'as a standalone binary'}`)
  }
)

cmd.parse(Bare.argv.slice(isDev ? 2 : 1))
