LOCATION_PREFIX = "@"
DEFAULT_LOCATION = "https://oydid.ownyourdata.eu"
VERSION = "0.5.2"
LOG_HASH_OPTIONS = {:digest => "sha2-256", :encode => "base58btc"}
DEFAULT_PUBLIC_RESOLVER = "https://dev.uniresolver.io/1.0/identifiers/"
# internal error code used by resolve_did/dag_update for a revoked DID
REVOKED_ERROR = 410
# guardrail: at any time a public key controls at most one active DID
KEY_IN_USE_ERROR = "public key already controls an active DID"