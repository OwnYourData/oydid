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
const multi_encode = (message, options) => __awaiter(void 0, void 0, void 0, function* () {
    const o = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    const method = o.encode;
    return "string";
});
exports.multi_encode = multi_encode;
const multi_hash = (message, options) => __awaiter(void 0, void 0, void 0, function* () {
    const opt = Object.assign({ encode: exports.DEFAULT_ENCODING, digest: exports.DEFAULT_DIGEST, simulate: false }, options);
    return "string";
});
exports.multi_hash = multi_hash;
