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
exports.decrypt = exports.hexToMulti = exports.didAuth = exports.create = exports.read = exports.DEFAULT_ENCODING = exports.DEFAULT_DIGEST = void 0;
const axios_1 = __importDefault(require("axios"));
const libsodium_wrappers_sumo_1 = require("libsodium-wrappers-sumo");
const base58_1 = require("multiformats/bases/base58");
// import bs58 from 'bs58';
exports.DEFAULT_DIGEST = "sha2-256";
exports.DEFAULT_ENCODING = "base58btc";
const read = (did, options) => __awaiter(void 0, void 0, void 0, function* () {
    const o = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    if (!did) {
        throw new Error("missing DID1");
    }
    return { doc: { "hello": "world" }, key: "asdf:qwer", log: "asdf" };
});
exports.read = read;
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
const didAuth = (did, key, regapi_url) => __awaiter(void 0, void 0, void 0, function* () {
    const url = regapi_url + "/did_auth";
    const body = { did: did, key: key };
    const result = yield axios_1.default.post(url, body);
    return result.data.access_token;
});
exports.didAuth = didAuth;
const hexToMulti = (hexKey) => __awaiter(void 0, void 0, void 0, function* () {
    yield libsodium_wrappers_sumo_1.ready;
    const keyBytes = (0, libsodium_wrappers_sumo_1.from_hex)(hexKey);
    const multiformatKey = base58_1.base58btc.encode(keyBytes);
    return multiformatKey;
});
exports.hexToMulti = hexToMulti;
const decrypt = (message, key, options) => __awaiter(void 0, void 0, void 0, function* () {
    yield libsodium_wrappers_sumo_1.ready;
    const privateKeyBytes = base58_1.base58btc.decode(key);
    const privateKey = privateKeyBytes.slice(privateKeyBytes.length - 32);
    const authHash = (0, libsodium_wrappers_sumo_1.crypto_hash_sha256)((0, libsodium_wrappers_sumo_1.from_string)('auth'));
    const authKey = (0, libsodium_wrappers_sumo_1.crypto_scalarmult_base)(authHash);
    const decryptedMessageBytes = (0, libsodium_wrappers_sumo_1.crypto_box_open_easy)((0, libsodium_wrappers_sumo_1.from_hex)(message.value), (0, libsodium_wrappers_sumo_1.from_hex)(message.nonce), authKey, privateKey);
    return (0, libsodium_wrappers_sumo_1.to_string)(decryptedMessageBytes);
});
exports.decrypt = decrypt;
