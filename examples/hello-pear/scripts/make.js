#!/usr/bin/env node
'use strict'

// Host detector, mirroring the template's scripts/make.js.
//
// It builds ONE target: the host's. That is deliberate in the template, and it is why a CI runner
// must invoke `make:<target>` directly -- calling `make` would build a single target and look like
// it had done the whole matrix.

const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')

const root = path.resolve(__dirname, '..')
const host = `${os.platform()}-${os.arch()}`
const supported = new Set([
  'darwin-arm64',
  'darwin-x64',
  'linux-arm64',
  'linux-x64',
  'win32-arm64',
  'win32-x64'
])

if (!supported.has(host)) {
  console.error(`Unsupported platform/arch: ${host}`)
  console.error('Supported targets: ' + [...supported].join(', '))
  process.exit(1)
}

const res = spawnSync('npm', ['run', `make:${host}`], { cwd: root, stdio: 'inherit' })
if (res.error) {
  console.error(res.error.message)
  process.exit(1)
}
if (res.status !== 0) process.exit(res.status || 1)
