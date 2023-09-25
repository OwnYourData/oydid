import axios from 'axios';

export const DEFAULT_DIGEST = "sha2-256";
export const DEFAULT_ENCODING = "base58btc";

export interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean
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

export const did_auth = async(did: string, key: string, regapi_url: string) : Promise<String> => {
    const url = regapi_url + "/did_auth";
    const body = {did: did, key: key};
    const result = await axios.post(url, body);
    return result.data.access_token;
}