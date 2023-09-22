export declare const DEFAULT_DIGEST = "sha2-256";
export declare const DEFAULT_ENCODING = "base58btc";
interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean;
}
export declare const multi_encode: (message: string, options?: Partial<ReadOptions>) => Promise<String>;
export declare const multi_hash: (message: string, options?: Partial<ReadOptions>) => Promise<String>;
export {};
