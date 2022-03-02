const { Resolver } = require('did-resolver');
const oydid = require('../dist/index.js');

const resolver = new Resolver({
  ...oydid.getResolver()
});

// resolve test-did
resolver.resolve('did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh').then(data =>
  console.log(JSON.stringify(data, undefined, 2))
);