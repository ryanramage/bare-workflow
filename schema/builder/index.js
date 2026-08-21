'use strict'

const path = require('bare-path')
const Hyperschema = require('hyperschema')
const HRPC = require('hrpc')

const generateTypes = require('./types.js')
const generateRPC = require('./rpc.js')

// Generates schema/spec/{hyperschema,hrpc}. The output is COMMITTED: it is the wire contract, so
// it should be reviewable in a diff and identical for everyone rather than a build artifact that
// varies by machine.
module.exports = function generateSpec(specDir) {
  const schemaDir = path.join(specDir, 'hyperschema')
  const rpcDir = path.join(specDir, 'hrpc')

  const schema = Hyperschema.from(schemaDir)
  generateTypes(schema)
  Hyperschema.toDisk(schema)

  const hrpc = HRPC.from(schemaDir, rpcDir)
  generateRPC(hrpc)
  HRPC.toDisk(hrpc)

  return { schemaDir, rpcDir }
}
