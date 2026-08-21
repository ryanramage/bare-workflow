const path = require('bare-path')
const generateSpec = require('../../schema/builder')

const out = generateSpec(path.join(__dirname, '../../schema/spec'))
console.log('generated', out.schemaDir, 'and', out.rpcDir)
