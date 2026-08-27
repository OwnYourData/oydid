const test = require('node:test')
const assert = require('node:assert/strict')
const { parseDid } = require('../dist/index.js')

const HASH = 'zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh'
const DID = `did:oyd:${HASH}`

test('parses a plain DID', () => {
  assert.deepEqual(parseDid(DID), { did: DID, didUrl: DID, method: 'oyd', id: HASH })
})

test('parses a fragment', () => {
  const parsed = parseDid(`${DID}#key-doc`)
  assert.equal(parsed.did, DID)
  assert.equal(parsed.fragment, 'key-doc')
  assert.equal(parsed.didUrl, `${DID}#key-doc`)
})

test('parses a query into params', () => {
  const parsed = parseDid(`${DID}?versionId=3&hl=abc`)
  assert.equal(parsed.did, DID)
  assert.equal(parsed.query, 'versionId=3&hl=abc')
  assert.deepEqual(parsed.params, { versionId: '3', hl: 'abc' })
})

test('parses a DID URL path', () => {
  const parsed = parseDid(`${DID}/some/path`)
  assert.equal(parsed.did, DID)
  assert.equal(parsed.path, '/some/path')
})

test('accepts the legacy location suffix and keeps it in the id', () => {
  const parsed = parseDid(`${DID}@https://did2.data-container.net`)
  assert.equal(parsed.method, 'oyd')
  assert.equal(parsed.id, `${HASH}@https://did2.data-container.net`)
  assert.equal(parsed.did, `${DID}@https://did2.data-container.net`)
  // a slash inside the location must not be read as a DID URL path
  assert.equal(parsed.path, undefined)
})

test('rejects the location suffix when it is switched off', () => {
  assert.equal(parseDid(`${DID}@did2.data-container.net`, false), null)
})

test('accepts the conformant percent-encoded location', () => {
  const parsed = parseDid(`${DID}%40did2.data-container.net`)
  assert.equal(parsed.id, `${HASH}%40did2.data-container.net`)
})

test('accepts a method-specific id with colons', () => {
  assert.equal(parseDid('did:oyd:a:b:c').id, 'a:b:c')
})

for (const bad of ['', 'not-a-did', 'did:oyd:', 'did:oyd:!!!', 'did::abc', 'did:OYD:abc', 'oyd:abc']) {
  test(`rejects ${JSON.stringify(bad)}`, () => {
    assert.equal(parseDid(bad), null)
  })
}

test('rejects non-string input', () => {
  assert.equal(parseDid(undefined), null)
  assert.equal(parseDid(42), null)
})
