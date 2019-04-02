"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
// Import only exactly what we need for packing / tree-shaking purposes.
const secp256k1_1 = require("bitcoin-ts/build/main/lib/crypto/secp256k1");
const webCrypto_1 = require("./webCrypto");
let cachedSecp256k1 = null;
function getSecp256k1() {
    return __awaiter(this, void 0, void 0, function* () {
        if (cachedSecp256k1 === null) {
            cachedSecp256k1 = createSecp256k1();
        }
        return cachedSecp256k1;
    });
}
function createSecp256k1() {
    return __awaiter(this, void 0, void 0, function* () {
        const { getRandomValues } = yield webCrypto_1.getWebCrypto();
        const seed = new Uint8Array(32);
        getRandomValues(seed);
        const instance = yield secp256k1_1.instantiateSecp256k1(seed);
        return instance;
    });
}
/**
 * @param privateKey hex string or buffer
 * @returns hex string
 */
function getPublicKeyFromPrivate(privateKey, compressed = true) {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const keyBytes = typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey;
        const publicKeyBytes = compressed
            ? yield secp256k1.derivePublicKeyCompressed(keyBytes)
            : yield secp256k1.derivePublicKeyUncompressed(keyBytes);
        const publicKeyHex = Buffer.from(publicKeyBytes).toString('hex');
        return publicKeyHex;
    });
}
exports.getPublicKeyFromPrivate = getPublicKeyFromPrivate;
function compressPublicKey(publicKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const keyBytes = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
        const compressed = secp256k1.compressPublicKey(keyBytes);
        const hex = Buffer.from(compressed).toString('hex');
        return hex;
    });
}
exports.compressPublicKey = compressPublicKey;
function decompressPublicKey(publicKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const keyBytes = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
        const decompressed = secp256k1.uncompressPublicKey(keyBytes);
        const hex = Buffer.from(decompressed).toString('hex');
        return hex;
    });
}
exports.decompressPublicKey = decompressPublicKey;
function signMessage(privateKey, message) {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const keyBytes = typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey;
        const sigBytes = yield secp256k1.signMessageHashDER(keyBytes, message);
        const sigHex = Buffer.from(sigBytes).toString('hex');
        return sigHex;
    });
}
exports.signMessage = signMessage;
function verifyMessage(signature, publicKey, messageHash) {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const sigBytes = typeof signature === 'string' ? Buffer.from(signature, 'hex') : signature;
        const keyBytes = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
        const result1 = secp256k1.verifySignatureDER(sigBytes, keyBytes, messageHash);
        // const result2 = secp256k1.verifySignatureDERLowS(sigBytes, keyBytes, messageHash)
        return result1;
    });
}
exports.verifyMessage = verifyMessage;
function generatePrivateKey() {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const { getRandomValues } = yield webCrypto_1.getWebCrypto();
        const privateKey = new Uint8Array(32);
        /**
         * Note: This is typical usage of libsecp256k1. Nearly every 256 number is a valid secp256k1
         * private key, so just wrap `validate` around a cryptographic-random generator. See any other
         * example usage of generating keys with libsecp256k1.
         * @see https://github.com/bitauth/bitcoin-ts/blob/cd8f44d639348d5f3917f7cf78b6e35f8c1b28ce/src/lib/crypto/secp256k1.ts#L327
         * @see https://github.com/MeadowSuite/Secp256k1.Net/blob/1fc63e5342e7ecbe185789cdc61811576398a6cc/Secp256k1.Net.Test/Tests.cs#L18
         * @see https://github.com/Bablakeluke/secp256k1-php/blob/d54a59463d38383667dac3703b264e5e88ce3d60/tests/TestCase.php#L32
         */
        do {
            getRandomValues(privateKey);
        } while (!secp256k1.validatePrivateKey(privateKey));
        return Buffer.from(privateKey);
    });
}
exports.generatePrivateKey = generatePrivateKey;
function computeSharedSecret(privateKey, publicKey) {
    return __awaiter(this, void 0, void 0, function* () {
        const secp256k1 = yield getSecp256k1();
        const privateKeyBytes = typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey;
        const publicKeyBytes = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
        const secret = yield secp256k1.computeEcdhSecret(publicKeyBytes, privateKeyBytes);
        const secretHex = Buffer.from(secret).toString('hex');
        return secretHex;
    });
}
exports.computeSharedSecret = computeSharedSecret;
//# sourceMappingURL=secp256k1-wasm.js.map