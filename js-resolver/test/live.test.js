// End-to-end tests against a real OYDID resolver.
// Skipped unless OYDID_LIVE=1, so `npm test` stays offline and deterministic.
//   npm run test:live
//   OYDID_LIVE=1 OYDID_RESOLVER=https://oydid-resolver.data-container.net npm test
const test = require('node:test')
const assert = require('node:assert/strict')
const { Resolver } = require('did-resolver')
const { getResolver, DEFAULT_RESOLVER_URL } = require('../dist/index.js')

const skip = process.env.OYDID_LIVE === '1' ? false : 'set OYDID_LIVE=1 to run'
const resolverUrl = process.env.OYDID_RESOLVER || DEFAULT_RESOLVER_URL
const DID = process.env.OYDID_TEST_DID || 'did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh'
const resolver = new Resolver({ ...getResolver({ resolverUrl, timeout: 15000 }) })

test('resolves a known DID', { skip }, async () => {
  const result = await resolver.resolve(DID)
  assert.equal(result.didResolutionMetadata.error, undefined)
  assert.equal(result.didDocument.id, DID)
  assert.equal(result.didResolutionMetadata.contentType, 'application/did+ld+json')
  // DID Core 7.1.3: the id of the returned document must be the DID asked for
  assert.equal(result.didDocument.id, DID)
  assert.ok(Array.isArray(result.didDocument.verificationMethod))
})

test('reports an unknown DID as notFound', { skip }, async () => {
  const unknown = 'did:oyd:zQmNOPExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
  const result = await resolver.resolve(unknown)
  assert.equal(result.didResolutionMetadata.error, 'notFound')
  assert.equal(result.didDocument, null)
})

test('carries the DID Core document metadata through', { skip }, async () => {
  const { didDocumentMetadata } = await resolver.resolve(DID)
  assert.equal(typeof didDocumentMetadata.versionId, 'string')
  assert.match(didDocumentMetadata.created, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  assert.equal(didDocumentMetadata.canonicalId, DID)
})

test('works against the content-negotiated /1.0/resolve/ binding', { skip }, async () => {
  const negotiated = new Resolver({ ...getResolver({ resolverUrl, path: '/1.0/resolve/', timeout: 15000 }) })
  const result = await negotiated.resolve(DID)
  assert.equal(result.didResolutionMetadata.error, undefined)
  assert.equal(result.didDocument.id, DID)
})
