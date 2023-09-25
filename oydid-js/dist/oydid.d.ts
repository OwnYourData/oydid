export declare const DEFAULT_DIGEST = "sha2-256";
export declare const DEFAULT_ENCODING = "base58btc";
export interface ReadOptions {
    encode: "base16" | "base32" | "base58btc" | "base64";
    digest: "sha2-256" | "sha2-512" | "sha3-224" | "sha3-256" | "sha3-384" | "sha3-512" | "blake2b-16" | "blake2b-32" | "blake2b-64";
    simulate: boolean;
}
interface DidDocument {
    doc: any;
    key: string;
    log: string;
}
interface Did {
    id: string;
    docKey: string;
    revKey: string;
}
export declare const read: (did: string, options?: Partial<ReadOptions>) => Promise<DidDocument>;
export declare const create: (content?: any, options?: Partial<ReadOptions>) => Promise<Did>;
export declare const did_auth: (did: string, key: string, regapi_url: string) => Promise<String>;
export {};
