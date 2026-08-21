'use strict'

// A launcher that runs the agent as a plain host subprocess.
//
// THIS LIVES UNDER test/ ON PURPOSE. It is host execution with no isolation whatsoever, which is
// exactly the "emulation" model this project rejects outright for running workflows. Keeping it
// out of lib/ means the product cannot select it even by accident -- there is no code path from a
// workflow to this file.
//
// What it is for: exercising the protocol, the agent, and the Sandbox lifecycle in milliseconds,
// without building an image. The container and microVM launchers implement the same two-method
// interface, so everything tested through here is the same code that runs under real isolation.

const { spawn } = require('bare-subprocess')
const path = require('bare-path')

const protocol = require('../../lib/protocol.js')

const AGENT = path.join(__dirname, '../../lib/agent/index.js')

class LocalLauncher {
  constructor(opts = {}) {
    this.tier = 'test-local'
    this.env = opts.env || {}
    this.cwd = opts.cwd || undefined
    this.proc = null
    this.stderr = ''
  }

  async spawn() {
    // Same fd shape as `podman run -i`: protocol on 0/1, diagnostics on 2.
    this.proc = spawn(Bare.argv[0], [AGENT], {
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: this.cwd,
      env: this.env
    })
    this.proc.stderr.on('data', (c) => {
      this.stderr += c
    })

    // protocol.bridge, not Duplex.from -- the latter is object-mode and breaks framing.
    const stream = protocol.bridge(this.proc.stdout, this.proc.stdin)

    return {
      stream,
      attestation: { tier: this.tier, agent: AGENT, note: 'NO ISOLATION -- test scaffolding only' },
      close: async ({ force = false } = {}) => {
        if (!this.proc) return
        try {
          this.proc.kill(force ? 'SIGKILL' : 'SIGTERM')
        } catch {}
        await new Promise((resolve) => {
          let done = false
          const finish = () => {
            if (!done) {
              done = true
              resolve()
            }
          }
          this.proc.on('exit', finish)
          setTimeout(() => {
            try {
              this.proc.kill('SIGKILL')
            } catch {}
            finish()
          }, 2000)
        })
        this.proc = null
      }
    }
  }
}

module.exports = { LocalLauncher, create: (o) => new LocalLauncher(o), AGENT }
