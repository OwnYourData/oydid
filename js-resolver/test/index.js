const { Resolver } = require('did-resolver');
const oydid = require('../dist/index.js');

const resolver = new Resolver({
  ...oydid.getResolver()
});

// resolve test-did
resolver.resolve('did:oyd:zQmZ8DEGQtJcpoQDMKYJkTiQn9dQLM2QzvmDQXuj8vCfvdj').then(data =>
  console.log(JSON.stringify(data, undefined, 2))
);