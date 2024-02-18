export const DEFAULT_DIGEST = "sha2-256";
export const DEFAULT_ENCODING = "base58btc";

interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean
}

import multibase from 'multibase';

export const multi_encode = async (message: string, options?: Partial<ReadOptions>) : Promise<String> => {
    const o: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }

    const method = o.encode;

    return "string";
}

export const multi_hash = async (message: string, options?: Partial<ReadOptions>) : Promise<String> => {
    const opt: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }

    return "string";
}