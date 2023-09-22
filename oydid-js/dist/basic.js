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
Object.defineProperty(exports, "__esModule", { value: true });
exports.multi_hash = exports.multi_encode = exports.DEFAULT_ENCODING = exports.DEFAULT_DIGEST = void 0;
exports.DEFAULT_DIGEST = "sha2-256";
exports.DEFAULT_ENCODING = "base58btc";
const libsodium_wrappers_1 = require("libsodium-wrappers");
const multi_encode = (message, options) => __awaiter(void 0, void 0, void 0, function* () {
    const o = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    const method = o.encode;
    return "asdf";
});
exports.multi_encode = multi_encode;
const multi_hash = (message, options) => __awaiter(void 0, void 0, void 0, function* () {
    const opt = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    yield libsodium_wrappers_1.ready; // Wait for libsodium to be ready
    // Convert the string to Uint8Array
    const data = new TextEncoder().encode(message);
    const method = opt.digest;
    var digest = "";
    switch (method) {
        case "sha2-256":
        case "blake2b-64":
            // Make sure the desired hash length is valid
            if (libsodium_wrappers_1.crypto_generichash_BYTES_MAX < 64) {
                throw new Error('Hash length is too large for BLAKE2b with this version of libsodium.');
            }
            const digest = (0, libsodium_wrappers_1.crypto_generichash)(64, data);
            break;
        default:
            throw new Error("unsupported digest: '" + method.toString() + "'");
            break;
    }
    const encoded = yield (0, exports.multi_encode)(digest, opt);
    return encoded;
});
exports.multi_hash = multi_hash;
