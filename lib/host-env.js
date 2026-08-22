'use strict'

// The environment handed to a HOST process we spawn -- podman, git, bare-build.
//
// Invariant 2 says we never inherit the caller's environment, so anything genuinely required has to
// be named here and justified. That part was always right. What was wrong was the SHAPE: six sites
// each wrote their own object literal of the form
//
//   { PATH: env.PATH, HOME: env.HOME, XDG_RUNTIME_DIR: env.XDG_RUNTIME_DIR }
//
// `bare-subprocess` builds the child environment with `${key}=${value}` over Object.entries, so a
// key whose value is `undefined` is not omitted -- it is passed as the literal string "undefined".
// XDG_RUNTIME_DIR is unset on macOS, so every one of those sites shipped `XDG_RUNTIME_DIR=undefined`
// and podman refused to start:
//
//   Failed to obtain podman configuration: lstat undefined: no such file or directory
//
// which `detect.js` then reported as "podman not found -- install podman". That is the worst kind of
// bug: the diagnosis actively misdirects, and it masks every other macOS finding behind it.
//
// So allowlisting is done by COPYING keys that are actually set, never by naming them as literal
// properties. `assertDefined` below is the invariant, asserted in tests.

const env = require('bare-env')
const os = require('bare-os')

// Needed by essentially everything we spawn.
const BASE = ['PATH', 'HOME', 'TMPDIR']

// The user session bus. systemd-run --user fails without these two:
// "Failed to connect to user scope bus via local transport: $DBUS_SESSION_BUS_ADDRESS and
// $XDG_RUNTIME_DIR not defined" -- found by the integration test skipping rather than passing.
const SESSION = ['XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS']

// Where rootless podman finds its own storage and registries config.
const CONFIG = ['XDG_CONFIG_HOME', 'XDG_DATA_HOME']

// On macOS and Windows podman is a REMOTE client talking to a service inside a Linux VM. A user who
// has selected a non-default connection has done so through one of these, and dropping them silently
// points us at a different machine than the one they configured.
const REMOTE = ['CONTAINER_HOST', 'CONTAINER_CONNECTION', 'CONTAINER_SSHKEY', 'DOCKER_HOST']

// The ssh transport to a podman machine uses an agent when the key is passphrase-protected.
const SSH = ['SSH_AUTH_SOCK']

// Windows has no HOME; podman.exe reads its containers.conf and its machine connection database out
// of APPDATA/LOCALAPPDATA, and libuv needs SystemRoot to spawn at all. Free to include now, and it
// retires the first Windows blocker in CLAUDE.md as a side effect.
const WINDOWS = ['USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'SystemRoot', 'SystemDrive', 'TEMP']

const KEYS = [...BASE, ...SESSION, ...CONFIG, ...REMOTE, ...SSH, ...WINDOWS]

// Copy the allowlisted keys that are genuinely set. An unset key is ABSENT from the result, never
// present-and-undefined and never an empty string -- podman treats an empty XDG_RUNTIME_DIR the same
// way it treats "undefined".
function hostEnv(extra = null, source = null) {
  const src = source || env
  const out = {}
  for (const key of KEYS) {
    const value = src[key]
    if (typeof value === 'string' && value !== '') out[key] = value
  }
  if (extra) {
    for (const [key, value] of Object.entries(extra)) {
      if (typeof value === 'string' && value !== '') out[key] = value
      else delete out[key] // an explicit undefined means "drop it", not "pass 'undefined'"
    }
  }
  return out
}

// The invariant, in one place so tests can assert it and callers can guard in development. A value
// of "undefined" is always a bug -- it is never something anyone meant to set.
function assertDefined(e) {
  for (const [key, value] of Object.entries(e)) {
    if (typeof value !== 'string') {
      throw new Error(`env ${key} is ${typeof value}, not a string -- it would be stringified`)
    }
    if (value === 'undefined' || value === 'null') {
      throw new Error(`env ${key} is the literal string ${JSON.stringify(value)}`)
    }
  }
  return e
}

// Whether a spawn of `file` can possibly succeed, so we can skip rather than spawn a binary we know
// is absent. This exists because of a measured teardown bug: bare-subprocess throws ENOENT for a
// missing program AND the bare process exits 144 afterwards, even when the throw is caught. So a
// test that spawns a known-absent binary reports failure for the whole run no matter how carefully
// it handles the error. Looking first is the only reliable answer.
//
// The thrown error also carries no program name ("no such file or directory"), which is why guards
// that match on stderr text cannot identify what was missing.
function which(file, e = null) {
  const fs = require('bare-fs')
  const path = require('bare-path')
  if (file.includes('/') || file.includes('\\')) {
    try {
      fs.statSync(file)
      return file
    } catch {
      return null
    }
  }
  const search = (e || hostEnv()).PATH || ''
  const exts = os.platform() === 'win32' ? ['.exe', '.com', '.cmd', '.bat', ''] : ['']
  for (const dir of search.split(os.platform() === 'win32' ? ';' : ':')) {
    if (!dir) continue
    for (const ext of exts) {
      const candidate = path.join(dir, file + ext)
      try {
        if (fs.statSync(candidate).isFile()) return candidate
      } catch {}
    }
  }
  return null
}

module.exports = { hostEnv, assertDefined, which, KEYS }
