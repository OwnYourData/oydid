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
exports.did_auth = exports.create = exports.read = exports.DEFAULT_ENCODING = exports.DEFAULT_DIGEST = void 0;
const axios_1 = __importDefault(require("axios"));
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
const did_auth = (did, key) => __awaiter(void 0, void 0, void 0, function* () {
    const url = "https://regapi.data-container.net/did_auth";
    const body = { did: did, key: key };
    const result = yield axios_1.default.post(url, body);
    return result.data.access_token;
});
exports.did_auth = did_auth;