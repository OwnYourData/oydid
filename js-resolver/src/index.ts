/**
 * `did:oyd` resolver plugin for the [`did-resolver`](https://github.com/decentralized-identity/did-resolver)
 * aggregator.
 *
 * OYDID links the identifier cryptographically to the DID Document and, via a
 * cryptographically linked provenance log, to the latest valid version of that
 * document. Verifying that chain is the job of an OYDID resolver; this library
 * is the HTTP client for one.
 *
 * It has no runtime dependencies: `did-resolver` is imported for types only and
 * `fetch` comes from the platform (Node >= 18).
 *
 * @see https://ownyourdata.github.io/oydid/ - did:oyd method specification
 * @see https://www.w3.org/TR/did-resolution/ - DID Resolution, HTTP(S) binding
 */
import type {
  DIDDocument,
  DIDDocumentMetadata,
  DIDResolutionMetadata,
  DIDResolutionOptions,
  DIDResolutionResult,
  DIDResolver,
  Params,
  ParsedDID,
  ResolverRegistry,
} from 'did-resolver'

/** DID method implemented by this resolver. */
export const METHOD = 'oyd'

/** Hosted OYDID resolver used when no other endpoint is configured. */
export const DEFAULT_RESOLVER_URL = 'https://resolver.ownyourdata.eu'

/**
 * Path of the `resolve` binding appended to {@link OydResolverConfig.resolverUrl}.
 *
 * `/1.0/identifiers/` always answers with a full DID Resolution Result and is
 * understood by every OYDID resolver as well as by the Universal Resolver, so it
 * is the safe default. Newer OYDID resolvers (uniresolver-plugin >= 0.5.2) also
 * serve the content-negotiated `/1.0/resolve/`.
 */
export const DEFAULT_PATH = '/1.0/identifiers/'

/** Milliseconds to wait for the resolver before giving up. */
export const DEFAULT_TIMEOUT = 10000

/**
 * Media types of the DID Resolution HTTP(S) binding. The first entry is the
 * legacy profile form that existing OYDID resolvers and the Universal Resolver
 * emit; the short form is the one newer implementations prefer.
 */
const ACCEPT_RESOLUTION_RESULT = [
  'application/ld+json;profile="https://w3id.org/did-resolution"',
  'application/did-resolution;q=0.9',
  'application/json;q=0.8',
].join(', ')

const MEDIA_TYPE_DOCUMENT_LD = 'application/did+ld+json'

/** Media types that denote a DID Document representation (DID Core 6). */
const DOCUMENT_MEDIA_TYPES = ['application/did', 'application/did+ld+json', 'application/did+json']

/** Resolution options this method does not implement; see the method spec. */
const UNSUPPORTED_OPTIONS = ['versionId', 'versionTime'] as const

/** Configuration accepted by {@link getResolver} and {@link resolve}. */
export interface OydResolverConfig {
  /**
   * Base URL of the OYDID resolver, without trailing slash.
   * Default: {@link DEFAULT_RESOLVER_URL}.
   */
  resolverUrl?: string
  /**
   * Path of the resolve binding, appended to `resolverUrl`.
   * Default: {@link DEFAULT_PATH}.
   */
  path?: string
  /** Request timeout in milliseconds. Default: {@link DEFAULT_TIMEOUT}. */
  timeout?: number
  /** Additional request headers, e.g. an `Authorization` for a private resolver. */
  headers?: Record<string, string>
  /**
   * Accept the non-conformant location suffix `did:oyd:<hash>@<location>`.
   *
   * `@` is not an `idchar` in the DID ABNF, so such a string is not a DID and is
   * rejected by generic parsers - including the one inside `did-resolver`. Set
   * this to `true` to let {@link resolve} handle the legacy form anyway; the
   * conformant spelling is the percent-encoded `%40`.
   * Default: `true`.
   */
  allowLocationSuffix?: boolean
}

interface ResolvedConfig extends Required<Omit<OydResolverConfig, 'headers'>> {
  headers: Record<string, string>
}

function applyDefaults(config: string | OydResolverConfig): ResolvedConfig {
  const c: OydResolverConfig = typeof config === 'string' ? { resolverUrl: config } : config
  const resolverUrl = (c.resolverUrl ?? DEFAULT_RESOLVER_URL).replace(/\/+$/, '')
  let path = c.path ?? DEFAULT_PATH
  if (!path.startsWith('/')) path = '/' + path
  if (!path.endsWith('/')) path = path + '/'
  return {
    resolverUrl,
    path,
    timeout: c.timeout ?? DEFAULT_TIMEOUT,
    headers: c.headers ?? {},
    allowLocationSuffix: c.allowLocationSuffix ?? true,
  }
}

// --- DID parsing ------------------------------------------------------------
// Own parser rather than did-resolver's `parse`, so that this package keeps zero
// runtime dependencies and can also accept the legacy `@location` form.

const PCT_ENCODED = '(?:%[0-9A-Fa-f]{2})'
const ID_CHAR = `(?:[A-Za-z0-9._-]|${PCT_ENCODED})`
const METHOD_SPECIFIC_ID = `(?:${ID_CHAR}*:)*${ID_CHAR}+`
const DID_PATTERN = new RegExp(`^did:([a-z0-9]+):(${METHOD_SPECIFIC_ID})$`)

function parseParams(query: string): Params {
  const params: Params = {}
  for (const pair of query.split('&')) {
    if (pair === '') continue
    const eq = pair.indexOf('=')
    const key = eq === -1 ? pair : pair.slice(0, eq)
    const value = eq === -1 ? '' : pair.slice(eq + 1)
    params[decodeURIComponent(key)] = decodeURIComponent(value)
  }
  return params
}

/**
 * Parse a DID or DID URL into its components.
 *
 * Returns `null` for anything that is not a syntactically valid DID URL. With
 * `allowLocationSuffix`, the OYDID-specific (and non-conformant) form
 * `did:oyd:<hash>@<location>` is accepted as well and the location is kept as
 * part of the method-specific id.
 */
export function parseDid(didUrl: string, allowLocationSuffix = true): ParsedDID | null {
  if (typeof didUrl !== 'string' || didUrl === '') return null

  let rest = didUrl
  let fragment: string | undefined
  let query: string | undefined
  let path: string | undefined

  const hash = rest.indexOf('#')
  if (hash !== -1) {
    fragment = rest.slice(hash + 1)
    rest = rest.slice(0, hash)
  }
  const question = rest.indexOf('?')
  if (question !== -1) {
    query = rest.slice(question + 1)
    rest = rest.slice(0, question)
  }

  // A location suffix may itself contain "/" (e.g. "@https://host/path"), so it
  // has to be split off before the DID URL path is looked for.
  let location: string | undefined
  const at = rest.indexOf('@')
  if (at !== -1) {
    if (!allowLocationSuffix) return null
    location = rest.slice(at)
    rest = rest.slice(0, at)
  } else {
    const slash = rest.indexOf('/')
    if (slash !== -1) {
      path = rest.slice(slash)
      rest = rest.slice(0, slash)
    }
  }

  const match = DID_PATTERN.exec(rest)
  if (match === null) return null
  const method = match[1]
  const id = match[2]
  if (method === undefined || id === undefined) return null

  const did = location === undefined ? `did:${method}:${id}` : `did:${method}:${id}${location}`
  const parsed: ParsedDID = {
    did,
    didUrl,
    method,
    id: location === undefined ? id : id + location,
  }
  if (path !== undefined) parsed.path = path
  if (query !== undefined) {
    parsed.query = query
    parsed.params = parseParams(query)
  }
  if (fragment !== undefined) parsed.fragment = fragment
  return parsed
}

// --- Resolution results -----------------------------------------------------

function errorResult(error: string, errorMessage?: string): DIDResolutionResult {
  const metadata: DIDResolutionMetadata =
    errorMessage === undefined ? { error } : { error, errorMessage }
  return { didResolutionMetadata: metadata, didDocument: null, didDocumentMetadata: {} }
}

/**
 * DID Core 7.1.3: a deactivated DID resolves successfully - the answer is
 * "deactivated", not an error. Only the document is gone.
 */
function deactivatedResult(): DIDResolutionResult {
  return {
    didResolutionMetadata: {},
    didDocument: null,
    didDocumentMetadata: { deactivated: true },
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * Turn whatever the resolver sent into a DID Resolution Result.
 *
 * Accepts both shapes of the HTTP(S) binding: a full resolution result (what
 * `/1.0/identifiers/` and a negotiated `/1.0/resolve/` return) and a bare DID
 * Document (what `/1.0/resolve/` returns for `Accept: application/did`).
 */
function normalize(body: unknown, contentType: string | null): DIDResolutionResult {
  if (!isRecord(body)) {
    return errorResult('internalError', 'resolver returned a non-object body')
  }

  if ('didDocument' in body || 'didResolutionMetadata' in body) {
    const rawDocument = body['didDocument']
    const document = isRecord(rawDocument) ? (rawDocument as DIDDocument) : null
    const metadata: DIDResolutionMetadata = isRecord(body['didResolutionMetadata'])
      ? { ...(body['didResolutionMetadata'] as DIDResolutionMetadata) }
      : {}
    const documentMetadata: DIDDocumentMetadata = isRecord(body['didDocumentMetadata'])
      ? (body['didDocumentMetadata'] as DIDDocumentMetadata)
      : {}

    if (typeof metadata.error === 'string') {
      return { didResolutionMetadata: metadata, didDocument: null, didDocumentMetadata: {} }
    }
    if (document === null) {
      // No document and no error: either a deactivated DID (metadata says so) or
      // a response we cannot make sense of.
      return documentMetadata.deactivated === true
        ? deactivatedResult()
        : errorResult('internalError', 'resolver returned neither a DID Document nor an error')
    }
    if (metadata.contentType === undefined) {
      // The response Content-Type describes the resolution result envelope
      // (application/ld+json, application/did-resolution), not the document it
      // carries - so it must not be copied here. DID Core: contentType is the
      // media type of the DID Document representation.
      metadata.contentType = MEDIA_TYPE_DOCUMENT_LD
    }
    return {
      didResolutionMetadata: metadata,
      didDocument: document,
      didDocumentMetadata: documentMetadata,
    }
  }

  if (typeof body['id'] === 'string') {
    // A bare DID Document: here the response Content-Type *is* the
    // representation, as long as it names one.
    const representation =
      contentType !== null && DOCUMENT_MEDIA_TYPES.includes(contentType)
        ? contentType
        : MEDIA_TYPE_DOCUMENT_LD
    return {
      didResolutionMetadata: { contentType: representation },
      didDocument: body as DIDDocument,
      didDocumentMetadata: {},
    }
  }

  return errorResult('internalError', 'resolver returned an unrecognised body')
}

/** Percent-encode the parts of a DID that would otherwise break the URL path. */
function encodeForPath(did: string): string {
  return encodeURI(did).replace(/\?/g, '%3F').replace(/#/g, '%23')
}

async function fetchResolution(
  did: string,
  cfg: ResolvedConfig,
  accept: string,
): Promise<DIDResolutionResult> {
  const url = `${cfg.resolverUrl}${cfg.path}${encodeForPath(did)}`
  let response: Response
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { Accept: accept, ...cfg.headers },
      redirect: 'follow',
      signal: AbortSignal.timeout(cfg.timeout),
    })
  } catch (cause) {
    const name = (cause as { name?: string }).name
    const message = (cause as { message?: string }).message ?? String(cause)
    if (name === 'TimeoutError' || name === 'AbortError') {
      return errorResult('internalError', `${cfg.resolverUrl} did not answer within ${cfg.timeout} ms`)
    }
    return errorResult('internalError', `cannot reach ${cfg.resolverUrl}: ${message}`)
  }

  // 410 Gone is how the HTTP(S) binding reports a revoked DID to a client that
  // asked for a document. A resolver configured with REVOKED_HTTP_STATUS=404
  // answers 404 instead - indistinguishable from "never existed" over HTTP, so
  // that case is reported as notFound.
  if (response.status === 410) return deactivatedResult()
  if (response.status === 404) return errorResult('notFound', `${did} is not known to ${cfg.resolverUrl}`)
  if (response.status === 400) return errorResult('invalidDid', `${cfg.resolverUrl} rejected ${did} as malformed`)
  if (response.status === 501) {
    return errorResult('featureNotSupported', `${cfg.resolverUrl} does not implement this request`)
  }
  if (!response.ok) {
    return errorResult('internalError', `${cfg.resolverUrl} answered HTTP ${response.status}`)
  }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    return errorResult('internalError', `${cfg.resolverUrl} returned a body that is not JSON`)
  }

  const contentType = response.headers.get('content-type')
  return normalize(body, contentType === null ? null : contentType.split(';')[0]?.trim() ?? null)
}

async function resolveParsed(
  parsed: ParsedDID,
  cfg: ResolvedConfig,
  options: DIDResolutionOptions,
): Promise<DIDResolutionResult> {
  if (parsed.method !== METHOD) {
    return errorResult('methodNotSupported', `this resolver only handles did:${METHOD}, not did:${parsed.method}`)
  }
  if (parsed.path !== undefined) {
    return errorResult('invalidDidUrl', 'OYDID does not define path components in DID URLs')
  }
  for (const key of UNSUPPORTED_OPTIONS) {
    if (options[key] !== undefined || parsed.params?.[key] !== undefined) {
      return errorResult(
        'featureNotSupported',
        `${key} is not defined for did:${METHOD}; a specific version is addressed as did:${METHOD}:<versionId>`,
      )
    }
  }
  const accept = typeof options.accept === 'string' ? options.accept : ACCEPT_RESOLUTION_RESULT
  return fetchResolution(parsed.did, cfg, accept)
}

/**
 * Resolve a `did:oyd` DID without going through the `did-resolver` aggregator.
 *
 * Unlike `new Resolver({...getResolver()}).resolve(did)` this accepts the legacy
 * location form `did:oyd:<hash>@<location>`, which is not a syntactically valid
 * DID and is therefore rejected by generic parsers.
 *
 * Never throws: transport and protocol failures are reported as
 * `didResolutionMetadata.error`.
 */
export async function resolve(
  did: string,
  config: string | OydResolverConfig = {},
  options: DIDResolutionOptions = {},
): Promise<DIDResolutionResult> {
  const cfg = applyDefaults(config)
  const parsed = parseDid(did, cfg.allowLocationSuffix)
  if (parsed === null) return errorResult('invalidDid', `${did} is not a valid DID`)
  return resolveParsed(parsed, cfg, options)
}

/**
 * Build the resolver registry entry for `did-resolver`.
 *
 * @param config - base URL of the OYDID resolver, or a {@link OydResolverConfig}.
 *
 * @example
 * ```ts
 * import { Resolver } from 'did-resolver'
 * import { getResolver } from 'oydid-did-resolver'
 *
 * const resolver = new Resolver({ ...getResolver() })
 * const result = await resolver.resolve('did:oyd:zQmaBZTghndXTgxNwfbdpVLWdFf6faYE4oeuN2zzXdQt1kh')
 * ```
 */
export function getResolver(config: string | OydResolverConfig = {}): ResolverRegistry {
  const cfg = applyDefaults(config)
  const resolver: DIDResolver = async (did, parsed, _resolver, options) => {
    // `did-resolver` has already parsed the DID URL; fall back to our own parser
    // when this function is called directly with something it could not.
    const effective = parsed ?? parseDid(did, cfg.allowLocationSuffix)
    if (effective === null) return errorResult('invalidDid', `${did} is not a valid DID`)
    return resolveParsed(effective, cfg, options ?? {})
  }
  return { [METHOD]: resolver }
}
