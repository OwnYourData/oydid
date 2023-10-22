export declare const DEFAULT_DIGEST = "sha2-256";
export declare const DEFAULT_ENCODING = "base58btc";
export interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean;
}
/**
 * structure of an encrypted message
 */
export interface CipherMessage {
    /**
     * value: cipher message
     */
    value: string;
    /**
     * nonce: number used only once
     */
    nonce: string;
}
/**
 * structure of a DID Document
 */
export interface DidDocument {
    /**
     * payload of DID Document
     */
    doc: any;
    /**
     * document and revocation key separated with :
     */
    key: string;
    /**
     * reference to log entry
     */
    log: string;
}
/**
 * structure of DID with private keys
 */
export interface Did {
    /**
     * DID string (in format did:oyd:123)
     */
    id: string;
    /**
     * private document key hex encoded
     */
    docKey: string;
    /**
     * private revocation key hex encoded
     */
    revKey: string;
}
/**
 * Sphereon structure for DID key
 */
export interface didKey {
    /**
     * key identifier
     */
    kid: string;
    /**
     * key management system
     */
    kms: string;
    /**
     * type of key (e.g., Ed25519)
     */
    type: string;
    /**
     * hex representation of public key
     */
    publicKeyHex: string;
    /**
     * hex representation of private key
     */
    privateKeyHex: string;
}
/**
 * response of Uniregistrar upon creating a DID
 */
export interface RegistrarResponse {
    /**
     * DID string (in format did:oyd:123)
     */
    did: string;
    /**
     * key identifier for DID controller
     */
    controllerKeyId: string;
    /**
     * array of available keys in DID Document
     */
    keys: didKey[];
}
/**
 * resolve DID to DID Document
 * @param did DID string (in format did:oyd:123)
 * @param options optional parameters
 * @returns DID Document
 */
export declare const read: (did: string, options?: Partial<ReadOptions>) => Promise<DidDocument>;
/**
 * create a new DID
 * @param content payload in the new DID Document
 * @param options optional parameters
 * @returns DID and private keys
 */
export declare const create: (content?: any, options?: Partial<ReadOptions>) => Promise<Did>;
/**
 *
 * @param did DID string (in format did:oyd:123)
 * @param key private key necessary for signing during authorization process
 * @param regapi_url RegAPI URL (only protocol and host, e.g. http://host.com)
 * @returns OAuth 2.0 Bearer Token
 */
export declare const didAuth: (did: string, key: string, regapi_url: string) => Promise<string>;
/**
 * convert hexadecimal encoded object to base58btc Multiformat encoding
 * @param hexKey hexadecimal encoded object
 * @param options optional parameters to specify preferred target encoding
 * @returns base58btc Multiformat encoded object
 */
export declare const hexToMulti: (hexKey: string, options?: Partial<ReadOptions>) => Promise<string>;
/**
 * decrypt a libsodium encrypted message
 * @param message cipher and nonce of encrypted message
 * @param key private key to decrypt message
 * @param options optional parameters
 * @returns decrypted message
 */
export declare const decrypt: (message: CipherMessage, key: string, options?: Partial<ReadOptions>) => Promise<string>;
