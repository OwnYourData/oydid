// Minimal example: resolve a did:oyd DID through the did-resolver aggregator.
//   node examples/resolve.js [did]
const { Resolver } = require('did-resolver')
const { getResolver } = require('../dist/index.js')

const did = process.argv[2] || 'did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh'
const resolver = new Resolver({ ...getResolver() })

resolver.resolve(did).then((result) => {
  console.log(JSON.stringify(result, undefined, 2))
})
