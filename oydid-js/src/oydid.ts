import axios from 'axios';
import { ready as sodiumReady, from_hex, from_string, to_string, crypto_box_open_easy, crypto_hash_sha256, crypto_scalarmult_base } from 'libsodium-wrappers-sumo';
import { base58btc } from 'multiformats/bases/base58';
// import bs58 from 'bs58';

export const DEFAULT_DIGEST = "sha2-256";
export const DEFAULT_ENCODING = "base58btc";

export interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean
}

export interface CipherMessage {
    value: string,
    nonce: string
}

interface DidDocument {
    doc: any,
    key: string,
    log: string
}

interface Did {
    id: string,
    docKey: string,
    revKey: string
}

interface didKey {
    kid: string,
    kms: string,
    type: string,
    publicKeyHex: string,
    privateKeyHex: string
}

interface RegistrarResponse {
    did: string,
    controllerKeyId: string,
    keys: didKey[]
}

export const read = async (did: string, options?: Partial<ReadOptions>) : Promise<DidDocument> => {
    const o: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }
    if (!did) {
        throw new Error("missing DID1")
    }

    return {doc:{"hello":"world"}, key:"asdf:qwer", log: "asdf"}
}

export const create = async(content?: any, options?: Partial<ReadOptions>) : Promise<Did> => {
    const url = "https://oydid-registrar.data-container.net/1.0/createIdentifier";
    const result = await axios.post(url, {});
    return {
        id: result.data.did, 
        docKey: result.data.keys[0].privateKeyHex, 
        revKey: result.data.keys[1].privateKeyHex
    }
}

export const didAuth = async(did: string, key: string, regapi_url: string) : Promise<string> => {
    const url = regapi_url + "/did_auth";
    const body = {did: did, key: key};
    const result = await axios.post(url, body);
    return result.data.access_token;
}

export const hexToMulti = async(hexKey: string) : Promise<string> => {
    await sodiumReady;
    const keyBytes = from_hex(hexKey);
    const multiformatKey = base58btc.encode(keyBytes);
    return multiformatKey;
}

export const decrypt = async(message: CipherMessage, key: string, options?: Partial<ReadOptions>) : Promise<string> => {
    await sodiumReady;
    const privateKeyBytes = base58btc.decode(key);
    const privateKey = privateKeyBytes.slice(privateKeyBytes.length - 32);
    const authHash = crypto_hash_sha256(from_string('auth'));
    const authKey = crypto_scalarmult_base(authHash);

    const decryptedMessageBytes = crypto_box_open_easy(
        from_hex(message.value), 
        from_hex(message.nonce),
        authKey,
        privateKey);

    return to_string(decryptedMessageBytes);

}