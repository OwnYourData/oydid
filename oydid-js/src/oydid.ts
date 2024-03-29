// import didJWT from 'did-jwt';
import axios from 'axios';
import { base58btc } from 'multiformats/bases/base58';

export const DEFAULT_DIGEST = "sha2-256";
export const DEFAULT_ENCODING = "base58btc";

export interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean
}

/**
 * structure of an encrypted message
 */
export interface CipherMessage {
    /**
     * value: cipher message
     */
    value: string,
    /**
     * nonce: number used only once
     */
    nonce: string
}

/**
 * structure of a DID Document
 */
export interface DidDocument {
    /**
     * payload of DID Document
     */
    doc: any,
    /**
     * document and revocation key separated with :
     */
    key: string,
    /**
     * reference to log entry
     */
    log: string
}

/**
 * structure of DID with private keys
 */
export interface Did {
    /**
     * DID string (in format did:oyd:123)
     */
    id: string,
    /**
     * private document key hex encoded
     */
    docKey: string,
    /**
     * private revocation key hex encoded
     */
    revKey: string
}

/**
 * Sphereon structure for DID key
 */
export interface didKey {
    /**
     * key identifier
     */
    kid: string,
    /**
     * key management system
     */
    kms: string,
    /**
     * type of key (e.g., Ed25519)
     */
    type: string,
    /**
     * hex representation of public key
     */
    publicKeyHex: string,
    /**
     * hex representation of private key
     */
    privateKeyHex: string
}

/**
 * response of Uniregistrar upon creating a DID
 */
export interface RegistrarResponse {
    /**
     * DID string (in format did:oyd:123)
     */
    did: string,
    /**
     * key identifier for DID controller
     */
    controllerKeyId: string,
    /**
     * array of available keys in DID Document
     */
    keys: didKey[]
}

/**
 * create a new DID
 * @param content payload in the new DID Document
 * @param options optional parameters
 * @returns DID and private keys
 */
export const create = async(content?: any, options?: Partial<ReadOptions>) : Promise<Did> => {
    const url = "https://oydid-registrar.data-container.net/1.0/createIdentifier";
    const result = await axios.post(url, {});
    return {
        id: result.data.did, 
        docKey: result.data.keys[0].privateKeyHex, 
        revKey: result.data.keys[1].privateKeyHex
    }
}

/**
 * resolve DID to DID Document
 * @param did DID string (in format did:oyd:123)
 * @param options optional parameters
 * @returns DID Document
 */
export const read = async (did: string, options?: Partial<ReadOptions>) : Promise<DidDocument> => {
    const o: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }
    if (!did) {
        throw new Error("missing DID")
    }

    return {doc:{"hello":"world"}, key:"asdf:qwer", log: "asdf"}
}

/**
 * update DID Document for existing DID
 * @param did DID string (in format did:oyd:123)
 * @param content payload of the updated DID Document
 * @param options optional parameters
 * @returns DID and private keys
 */
export const update = async (did: string, content: any, options?: Partial<ReadOptions>) : Promise<Did> => {
    const o: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }
    if (!did) {
        throw new Error("missing DID")
    }

    return {
        id: did, 
        docKey: "", 
        revKey: ""
    }
}

/**
 * deactivate DID
 * @param did DID string (in format did:oyd:123)
 * @param options optional parameters
 * @returns DID
 */
export const deactivate = async (did: string, options?: Partial<ReadOptions>) : Promise<Did> => {
    const o: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }
    if (!did) {
        throw new Error("missing DID")
    }

    return {
        id: did, 
        docKey: "", 
        revKey: ""
    }
}

/**
 * encrypt a message using libsodium
 * @param payload to encrypt
 * @param option parameters with public key for encryption
 * @returns cipher and nonce of encrypted message
 */
export const encrypt = async(payload: string, options: Partial<ReadOptions>) : Promise<any> => {
    if (!payload) {
        throw new Error("missing payload")
    }
    const url = "https://oydid.ownyourdata.eu/helper/encrypt";
    const body = {message: payload, key: ""};
    const result = await axios.post(url, body);
    return {
        cipher: result.data.cipher,
        nonce: result.data.nonce
    }
}

/**
 * decrypt a libsodium encrypted message
 * @param message cipher and nonce of encrypted message
 * @param key private key to decrypt message
 * @param options optional parameters
 * @returns decrypted message
 */
export const decrypt = async(message: CipherMessage, key: string, options?: Partial<ReadOptions>) : Promise<string> => {
    const url = "https://oydid.ownyourdata.eu/helper/decrypt";
    const body = {message: message, key: key};
    const result = await axios.post(url, body);
    return JSON.stringify(result.data, null, 0);
}

/**
 * sign a message
 * @param payload to sign
 * @param option parameters with private key for signing
 * @returns signature of payload
 */
export const sign = async(payload: string, options: Partial<ReadOptions>) : Promise<string> => {
    if (!payload) {
        throw new Error("missing payload")
    }
    return "string";
}

/**
 * verify signature for a message
 * @param hexKey hexadecimal encoded object
 * @param options optional parameters to specify preferred target encoding
 * @returns base58btc Multiformat encoded object
 */
export const verify = async(message: string, signature: string, options?: Partial<ReadOptions>) : Promise<boolean> => {
    if (!message) {
        throw new Error("missing message")
    }
    if (!signature) {
        throw new Error("missing signature")
    }
    return true;
}

/**
 * @param did DID string (in format did:oyd:123)
 * @param key private key necessary for signing during authorization process
 * @param regapi_url RegAPI URL (only protocol and host, e.g. http://host.com)
 * @returns OAuth 2.0 Bearer Token
 */
export const didAuth = async(did: string, key: string, regapi_url: string) : Promise<string> => {
    const url = regapi_url + (regapi_url.endsWith('/') ? "" : "/") + "did_auth";
    const body = {did: did, key: key};
    const result = await axios.post(url, body);
    return result.data.access_token;
}

/**
 * convert hexadecimal encoded object to base58btc Multiformat encoding
 * @param hexKey hexadecimal encoded object
 * @param options optional parameters to specify preferred target encoding
 * @returns base58btc Multiformat encoded object
 */
export const hexToMulti = async(hexKey: string, options?: Partial<ReadOptions>) : Promise<string> => {
    const keyBytes = Buffer.from(hexKey, "hex");
    // const keyBytes = didJWT.hexToBytes(hexKey);
    const multiformatKey = base58btc.encode(keyBytes);
    return multiformatKey;
}
