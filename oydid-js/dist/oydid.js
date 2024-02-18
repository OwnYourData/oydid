"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hexToMulti = exports.didAuth = exports.verify = exports.sign = exports.decrypt = exports.encrypt = exports.deactivate = exports.update = exports.read = exports.create = exports.DEFAULT_ENCODING = exports.DEFAULT_DIGEST = void 0;
const did_jwt_1 = __importDefault(require("did-jwt"));
const axios_1 = __importDefault(require("axios"));
const base58_1 = require("multiformats/bases/base58");
exports.DEFAULT_DIGEST = "sha2-256";
exports.DEFAULT_ENCODING = "base58btc";
/**
 * create a new DID
 * @param content payload in the new DID Document
 * @param options optional parameters
 * @returns DID and private keys
 */
const create = (content, options) => __awaiter(void 0, void 0, void 0, function* () {
    const url = "https://oydid-registrar.data-container.net/1.0/createIdentifier";
    const result = yield axios_1.default.post(url, {});
    return {
        id: result.data.did,
        docKey: result.data.keys[0].privateKeyHex,
        revKey: result.data.keys[1].privateKeyHex
    };
});
exports.create = create;
/**
 * resolve DID to DID Document
 * @param did DID string (in format did:oyd:123)
 * @param options optional parameters
 * @returns DID Document
 */
const read = (did, options) => __awaiter(void 0, void 0, void 0, function* () {
    const o = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    if (!did) {
        throw new Error("missing DID");
    }
    return { doc: { "hello": "world" }, key: "asdf:qwer", log: "asdf" };
});
exports.read = read;
/**
 * update DID Document for existing DID
 * @param did DID string (in format did:oyd:123)
 * @param content payload of the updated DID Document
 * @param options optional parameters
 * @returns DID and private keys
 */
const update = (did, content, options) => __awaiter(void 0, void 0, void 0, function* () {
    const o = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    if (!did) {
        throw new Error("missing DID");
    }
    return {
        id: did,
        docKey: "",
        revKey: ""
    };
});
exports.update = update;
/**
 * deactivate DID
 * @param did DID string (in format did:oyd:123)
 * @param options optional parameters
 * @returns DID
 */
const deactivate = (did, options) => __awaiter(void 0, void 0, void 0, function* () {
    const o = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    if (!did) {
        throw new Error("missing DID");
    }
    return {
        id: did,
        docKey: "",
        revKey: ""
    };
});
exports.deactivate = deactivate;
/**
 * encrypt a message using libsodium
 * @param payload to encrypt
 * @param option parameters with public key for encryption
 * @returns cipher and nonce of encrypted message
 */
const encrypt = (payload, options) => __awaiter(void 0, void 0, void 0, function* () {
    if (!payload) {
        throw new Error("missing payload");
    }
    const url = "https://oydid.ownyourdata.eu/helper/encrypt";
    const body = { message: payload, key: "" };
    const result = yield axios_1.default.post(url, body);
    return {
        cipher: result.data.cipher,
        nonce: result.data.nonce
    };
});
exports.encrypt = encrypt;
/**
 * decrypt a libsodium encrypted message
 * @param message cipher and nonce of encrypted message
 * @param key private key to decrypt message
 * @param options optional parameters
 * @returns decrypted message
 */
const decrypt = (message, key, options) => __awaiter(void 0, void 0, void 0, function* () {
    const url = "https://oydid.ownyourdata.eu/helper/decrypt";
    const body = { message: message, key: key };
    const result = yield axios_1.default.post(url, body);
    return JSON.stringify(result.data, null, 0);
});
exports.decrypt = decrypt;
/**
 * sign a message
 * @param payload to sign
 * @param option parameters with private key for signing
 * @returns signature of payload
 */
const sign = (payload, options) => __awaiter(void 0, void 0, void 0, function* () {
    if (!payload) {
        throw new Error("missing payload");
    }
    return "string";
});
exports.sign = sign;
/**
 * verify signature for a message
 * @param hexKey hexadecimal encoded object
 * @param options optional parameters to specify preferred target encoding
 * @returns base58btc Multiformat encoded object
 */
const verify = (message, signature, options) => __awaiter(void 0, void 0, void 0, function* () {
    if (!message) {
        throw new Error("missing message");
    }
    if (!signature) {
        throw new Error("missing signature");
    }
    return true;
});
exports.verify = verify;
/**
 * @param did DID string (in format did:oyd:123)
 * @param key private key necessary for signing during authorization process
 * @param regapi_url RegAPI URL (only protocol and host, e.g. http://host.com)
 * @returns OAuth 2.0 Bearer Token
 */
const didAuth = (did, key, regapi_url) => __awaiter(void 0, void 0, void 0, function* () {
    const url = regapi_url + (regapi_url.endsWith('/') ? "" : "/") + "did_auth";
    const body = { did: did, key: key };
    const result = yield axios_1.default.post(url, body);
    return result.data.access_token;
});
exports.didAuth = didAuth;
/**
 * convert hexadecimal encoded object to base58btc Multiformat encoding
 * @param hexKey hexadecimal encoded object
 * @param options optional parameters to specify preferred target encoding
 * @returns base58btc Multiformat encoded object
 */
const hexToMulti = (hexKey, options) => __awaiter(void 0, void 0, void 0, function* () {
    const keyBytes = did_jwt_1.default.hexToBytes(hexKey);
    const multiformatKey = base58_1.base58btc.encode(keyBytes);
    return multiformatKey;
});
exports.hexToMulti = hexToMulti;
