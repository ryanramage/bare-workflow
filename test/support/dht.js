'use strict'

// A local DHT plus a seeding peer, so the publish path can be tested for real without touching the
// live network or a real release line.
//
// The seeder is not scaffolding to make a test pass -- it is the thing the docs require. `pear seed`
// must run somewhere permanent, because staging is not finished until another peer has replicated
// the new blocks. Without a peer here, publishing correctly times out (there is a test for exactly
// that). So this stands in for the always-online farm member, which is itself one of the more
// interesting things a P2P build farm could offer.

const fs = require('bare-fs')

function available() {
  try {
    require('@hyperswarm/testnet')
    require('corestore')
    require('hyperdrive')
    require('hyperswarm')
    return true
  } catch {
    return false
  }
}

// Derive the drive key the way pear-ci will, so the seeder can be online BEFORE staging starts.
// The identity is a pure function of (primaryKey, name), which is what makes this possible.
async function driveKey(primaryKey, name, storage) {
  const Corestore = require('corestore')
  const Hyperdrive = require('hyperdrive')

  const store = new Corestore(storage, { primaryKey, unsafe: true })
  await store.ready()
  const drive = new Hyperdrive(store.namespace(name))
  await drive.ready()
  const key = drive.core.key
  await drive.close()
  await store.close()
  return key
}

// Returns { bootstrap, destroy }. `destroy` is idempotent enough to call from a finally block.
async function testnetWithSeeder(primaryKey, name, base) {
  const createTestnet = require('@hyperswarm/testnet')
  const Corestore = require('corestore')
  const Hyperdrive = require('hyperdrive')
  const Hyperswarm = require('hyperswarm')

  fs.mkdirSync(base, { recursive: true })
  const testnet = await createTestnet(3)
  const key = await driveKey(primaryKey, name, base + '/derive')

  const store = new Corestore(base + '/seed')
  const drive = new Hyperdrive(store, key)
  await drive.ready()
  const swarm = new Hyperswarm({ bootstrap: testnet.bootstrap })
  swarm.on('connection', (c) => store.replicate(c))
  swarm.join(drive.discoveryKey, { client: true, server: true })

  // Started WITHOUT awaiting, which took a debugging round to find: on a drive that has never been
  // written the blobs core does not exist yet, so `await drive.getBlobs()` never resolves and the
  // seeder hangs before it is online -- looking exactly like a network failure.
  drive.core.download({ start: 0, end: -1 })
  drive
    .getBlobs()
    .then((b) => b.core.download({ start: 0, end: -1 }))
    .catch(() => {})

  return {
    bootstrap: testnet.bootstrap,
    address: testnet.bootstrap.map((node) => node.host + ':' + node.port).join(','),
    link: 'pear://' + drive.core.id,
    async destroy() {
      await swarm.destroy()
      await drive.close()
      await store.close()
      await testnet.destroy()
    }
  }
}

module.exports = { available, driveKey, testnetWithSeeder }
