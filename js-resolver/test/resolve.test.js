const test = require('node:test')
const assert = require('node:assert/strict')
const { Resolver } = require('did-resolver')
const { getResolver, resolve, METHOD, DEFAULT_RESOLVER_URL, DEFAULT_PATH } = require('../dist/index.js')

const HASH = 'zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh'
const DID = `did:oyd:${HASH}`

const DOCUMENT = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  verificationMethod: [{ id: `${DID}#key-doc`, type: 'Ed25519VerificationKey2020', controller: DID }],
}
const RESULT = {
  didResolutionMetadata: {},
  didDocument: DOCUMENT,
  didDocumentMetadata: { versionId: HASH, created: '2022-01-03T15:45:36Z' },
}

/** Replace global fetch for the duration of `fn` and record every call. */
async function withFetch(handler, fn) {
  const calls = []
  const previous = globalThis.fetch
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init })
    return handler(url, init)
  }
  try {
    return await fn(calls)
  } finally {
    globalThis.fetch = previous
  }
}

const respond = (body, status = 200, contentType = 'application/ld+json; charset=utf-8') =>
  new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'content-type': contentType },
  })

const always = (response) => () => response

// --- happy path -------------------------------------------------------------

test('returns the resolution result and fills in contentType', async () => {
  await withFetch(always(respond(RESULT)), async (calls) => {
    const result = await resolve(DID)
    assert.equal(result.didDocument.id, DID)
    // the envelope is application/ld+json, the document representation is not
    assert.equal(result.didResolutionMetadata.contentType, 'application/did+ld+json')
    assert.equal(result.didDocumentMetadata.versionId, HASH)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].url, `${DEFAULT_RESOLVER_URL}${DEFAULT_PATH}${DID}`)
  })
})

test('does not overwrite a contentType the resolver already set', async () => {
  const body = { ...RESULT, didResolutionMetadata: { contentType: 'application/did+json' } }
  await withFetch(always(respond(body)), async () => {
    const result = await resolve(DID)
    assert.equal(result.didResolutionMetadata.contentType, 'application/did+json')
  })
})

test('wraps a bare DID Document into a resolution result', async () => {
  await withFetch(always(respond(DOCUMENT, 200, 'application/did')), async () => {
    const result = await resolve(DID)
    assert.equal(result.didDocument.id, DID)
    assert.equal(result.didResolutionMetadata.contentType, 'application/did')
    assert.deepEqual(result.didDocumentMetadata, {})
  })
})

test('sends the resolution result media types by default', async () => {
  await withFetch(always(respond(RESULT)), async (calls) => {
    await resolve(DID)
    const accept = calls[0].init.headers.Accept
    assert.match(accept, /profile="https:\/\/w3id\.org\/did-resolution"/)
    assert.match(accept, /application\/did-resolution/)
  })
})

test('forwards an explicit accept option', async () => {
  await withFetch(always(respond(DOCUMENT, 200, 'application/did')), async (calls) => {
    await resolve(DID, {}, { accept: 'application/did' })
    assert.equal(calls[0].init.headers.Accept, 'application/did')
  })
})

// --- deactivation -----------------------------------------------------------

test('reports a deactivated DID from a 200 answer, without an error', async () => {
  const body = { didDocument: null, didResolutionMetadata: {}, didDocumentMetadata: { deactivated: true } }
  await withFetch(always(respond(body)), async () => {
    const result = await resolve(DID)
    assert.equal(result.didDocument, null)
    assert.equal(result.didDocumentMetadata.deactivated, true)
    assert.equal(result.didResolutionMetadata.error, undefined)
  })
})

test('reports a deactivated DID from HTTP 410', async () => {
  await withFetch(always(respond({ error: 'revoked' }, 410)), async () => {
    const result = await resolve(DID)
    assert.equal(result.didDocument, null)
    assert.equal(result.didDocumentMetadata.deactivated, true)
    assert.equal(result.didResolutionMetadata.error, undefined)
  })
})

// --- errors -----------------------------------------------------------------

test('maps HTTP 404 to notFound', async () => {
  await withFetch(always(respond({ error: 'not found' }, 404)), async () => {
    const result = await resolve(DID)
    assert.equal(result.didResolutionMetadata.error, 'notFound')
    assert.equal(result.didDocument, null)
  })
})

test('maps HTTP 400 to invalidDid', async () => {
  await withFetch(always(respond({ error: 'bad' }, 400)), async () => {
    assert.equal((await resolve(DID)).didResolutionMetadata.error, 'invalidDid')
  })
})

test('maps HTTP 501 to featureNotSupported', async () => {
  await withFetch(always(respond({ error: 'nope' }, 501)), async () => {
    assert.equal((await resolve(DID)).didResolutionMetadata.error, 'featureNotSupported')
  })
})

test('maps HTTP 500 to internalError', async () => {
  await withFetch(always(respond({ error: 'boom' }, 500)), async () => {
    const result = await resolve(DID)
    assert.equal(result.didResolutionMetadata.error, 'internalError')
    assert.match(result.didResolutionMetadata.errorMessage, /HTTP 500/)
  })
})

test('passes an error stated by the resolver through', async () => {
  const body = { didResolutionMetadata: { error: 'notFound' }, didDocument: null, didDocumentMetadata: {} }
  await withFetch(always(respond(body)), async () => {
    assert.equal((await resolve(DID)).didResolutionMetadata.error, 'notFound')
  })
})

test('reports a body that is not JSON as internalError', async () => {
  await withFetch(always(respond('<html>502</html>', 200, 'text/html')), async () => {
    const result = await resolve(DID)
    assert.equal(result.didResolutionMetadata.error, 'internalError')
    assert.match(result.didResolutionMetadata.errorMessage, /not JSON/)
  })
})

test('reports a 200 without document and without error as internalError', async () => {
  const body = { didResolutionMetadata: {}, didDocument: null, didDocumentMetadata: {} }
  await withFetch(always(respond(body)), async () => {
    assert.equal((await resolve(DID)).didResolutionMetadata.error, 'internalError')
  })
})

test('never throws when the network fails', async () => {
  await withFetch(() => { throw new TypeError('fetch failed') }, async () => {
    const result = await resolve(DID)
    assert.equal(result.didResolutionMetadata.error, 'internalError')
    assert.match(result.didResolutionMetadata.errorMessage, /cannot reach/)
  })
})

test('reports a timeout as internalError', async () => {
  const timeout = () => {
    const e = new Error('The operation was aborted due to timeout')
    e.name = 'TimeoutError'
    throw e
  }
  await withFetch(timeout, async () => {
    const result = await resolve(DID, { timeout: 250 })
    assert.equal(result.didResolutionMetadata.error, 'internalError')
    assert.match(result.didResolutionMetadata.errorMessage, /within 250 ms/)
  })
})

// --- input validation (no request must be made) -----------------------------

const refuse = () => { throw new Error('no request expected') }

test('rejects a malformed DID before contacting the resolver', async () => {
  await withFetch(refuse, async (calls) => {
    assert.equal((await resolve('did:oyd:!!!')).didResolutionMetadata.error, 'invalidDid')
    assert.equal(calls.length, 0)
  })
})

test('rejects another DID method', async () => {
  await withFetch(refuse, async () => {
    const result = await resolve('did:key:z6Mkabc')
    assert.equal(result.didResolutionMetadata.error, 'methodNotSupported')
  })
})

test('rejects a DID URL path', async () => {
  await withFetch(refuse, async () => {
    const result = await resolve(`${DID}/whoami`)
    assert.equal(result.didResolutionMetadata.error, 'invalidDidUrl')
  })
})

for (const key of ['versionId', 'versionTime']) {
  test(`rejects the ${key} option as featureNotSupported`, async () => {
    await withFetch(refuse, async (calls) => {
      const result = await resolve(DID, {}, { [key]: '3' })
      assert.equal(result.didResolutionMetadata.error, 'featureNotSupported')
      assert.equal(calls.length, 0)
    })
  })

  test(`rejects ?${key}= in the DID URL as featureNotSupported`, async () => {
    await withFetch(refuse, async () => {
      const result = await resolve(`${DID}?${key}=3`)
      assert.equal(result.didResolutionMetadata.error, 'featureNotSupported')
    })
  })
}

// --- configuration ----------------------------------------------------------

test('accepts a bare URL string, as before 0.3.0', async () => {
  await withFetch(always(respond(RESULT)), async (calls) => {
    await resolve(DID, 'https://resolver.example/')
    assert.equal(calls[0].url, `https://resolver.example${DEFAULT_PATH}${DID}`)
  })
})

test('normalises resolverUrl and path', async () => {
  await withFetch(always(respond(RESULT)), async (calls) => {
    await resolve(DID, { resolverUrl: 'https://resolver.example///', path: '1.0/resolve' })
    assert.equal(calls[0].url, `https://resolver.example/1.0/resolve/${DID}`)
  })
})

test('merges extra headers', async () => {
  await withFetch(always(respond(RESULT)), async (calls) => {
    await resolve(DID, { headers: { Authorization: 'Bearer t' } })
    assert.equal(calls[0].init.headers.Authorization, 'Bearer t')
    assert.ok(calls[0].init.headers.Accept)
  })
})

test('percent-encodes characters that would break the URL path', async () => {
  await withFetch(always(respond(RESULT)), async (calls) => {
    await resolve(`did:oyd:${HASH}@https://did2.data-container.net`)
    assert.ok(calls[0].url.endsWith(`${HASH}@https://did2.data-container.net`))
    assert.ok(!calls[0].url.includes(' '))
  })
})

// --- did-resolver registry --------------------------------------------------

test('registers itself under the oyd method', () => {
  const registry = getResolver()
  assert.deepEqual(Object.keys(registry), [METHOD])
  assert.equal(typeof registry.oyd, 'function')
})

test('works through the did-resolver aggregator', async () => {
  await withFetch(always(respond(RESULT)), async () => {
    const resolver = new Resolver({ ...getResolver() })
    const result = await resolver.resolve(DID)
    assert.equal(result.didDocument.id, DID)
  })
})

test('the aggregator rejects the legacy @ location before we see it', async () => {
  await withFetch(refuse, async () => {
    const resolver = new Resolver({ ...getResolver() })
    const result = await resolver.resolve(`${DID}@did2.data-container.net`)
    // did-resolver's own parser has no idea what "@" is - documented limitation
    assert.equal(result.didResolutionMetadata.error, 'invalidDid')
  })
})
