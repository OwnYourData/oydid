export const DEFAULT_DIGEST = "sha2-256";
export const DEFAULT_ENCODING = "base58btc";

interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean
}

import { ready, crypto_generichash, crypto_generichash_BYTES_MAX } from 'libsodium-wrappers';
import multibase from 'multibase';

export const multi_encode = async (message: string, options?: Partial<ReadOptions>) : Promise<String> => {
    const o: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }

    const method = o.encode;

    return "asdf";
}

export const multi_hash = async (message: string, options?: Partial<ReadOptions>) : Promise<String> => {
    const opt: ReadOptions = {
        encode: DEFAULT_ENCODING,
        digest: DEFAULT_DIGEST,
        simulate: false,
        ...options,
    }
    await ready;  // Wait for libsodium to be ready

    // Convert the string to Uint8Array
    const data = new TextEncoder().encode(message);

    const method = opt.digest;
    var digest = "";
    switch(method) {
        case "sha2-256":

        case "blake2b-64":
            // Make sure the desired hash length is valid
            if (crypto_generichash_BYTES_MAX < 64) {
                throw new Error('Hash length is too large for BLAKE2b with this version of libsodium.');
            }
            const digest = crypto_generichash(64, data);
            break;
        default:
            throw new Error("unsupported digest: '" + method.toString() + "'");
            break;
    }
    const encoded = await multi_encode(digest, opt);

    return encoded;
}