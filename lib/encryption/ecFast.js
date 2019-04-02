"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = require("assert");
const webCrypto_1 = require("./webCrypto");
const secp256k1_wasm_1 = require("./secp256k1-wasm");
const DEBUG_CHECK = true;
function aes256CbcEncrypt(iv, key, plaintext) {
    return __awaiter(this, void 0, void 0, function* () {
        const { subtle } = yield webCrypto_1.getWebCrypto();
        const cryptoKey = yield subtle.importKey('raw', key, { name: 'AES-CBC', length: 256 }, false, ['encrypt']);
        const cipher = yield subtle.encrypt({ name: 'AES-CBC', iv }, cryptoKey, plaintext);
        if (DEBUG_CHECK) {
            const nodeCrypto = yield Promise.resolve().then(() => __importStar(require('crypto')));
            const _cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv);
            const _res = Buffer.concat([_cipher.update(plaintext), _cipher.final()]);
            const _resHex = _res.toString('hex');
            const resHex = Buffer.from(cipher).toString('hex');
            assert_1.strict.equal(resHex, _resHex);
        }
        return Buffer.from(cipher);
    });
}
function aes256CbcDecrypt(iv, key, ciphertext) {
    return __awaiter(this, void 0, void 0, function* () {
        const { subtle } = yield webCrypto_1.getWebCrypto();
        const cryptoKey = yield subtle.importKey('raw', key, { name: 'AES-CBC', length: 256 }, false, ['decrypt']);
        const plaintext = yield subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, ciphertext);
        if (DEBUG_CHECK) {
            const nodeCrypto = yield Promise.resolve().then(() => __importStar(require('crypto')));
            const _cipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv);
            const _res = Buffer.concat([_cipher.update(ciphertext), _cipher.final()]).toString('hex');
            const res = Buffer.from(plaintext).toString('hex');
            assert_1.strict.equal(res, _res);
        }
        return Buffer.from(plaintext);
    });
}
function hmacSha256(keyData, content) {
    return __awaiter(this, void 0, void 0, function* () {
        const { subtle } = yield webCrypto_1.getWebCrypto();
        const key = yield subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const sig = yield subtle.sign('HMAC', key, content);
        if (DEBUG_CHECK) {
            const nodeCrypto = yield Promise.resolve().then(() => __importStar(require('crypto')));
            const expected = nodeCrypto.createHmac('sha256', keyData).update(content).digest().toString('hex');
            const actual = Buffer.from(sig).toString('hex');
            assert_1.strict.equal(actual, expected);
        }
        return Buffer.from(sig);
    });
}
function equalConstTime(b1, b2) {
    if (b1.length !== b2.length) {
        return false;
    }
    let res = 0;
    for (let i = 0; i < b1.length; i++) {
        res |= b1[i] ^ b2[i]; // jshint ignore:line
    }
    return res === 0;
}
function sharedSecretToKeys(sharedSecret) {
    return __awaiter(this, void 0, void 0, function* () {
        const { subtle } = yield webCrypto_1.getWebCrypto();
        // generate mac and encryption key from shared secret
        const hashedSecretArr = yield subtle.digest('SHA-512', sharedSecret);
        const hashedSecret = new Uint8Array(hashedSecretArr);
        if (DEBUG_CHECK) {
            const nodeCrypto = yield Promise.resolve().then(() => __importStar(require('crypto')));
            const expected = nodeCrypto.createHash('sha512').update(sharedSecret).digest().toString('hex');
            const actual = Buffer.from(hashedSecret).toString('hex');
            assert_1.strict.equal(actual, expected);
        }
        return {
            encryptionKey: hashedSecret.slice(0, 32),
            hmacKey: hashedSecret.slice(32)
        };
    });
}
function getHexFromBN(bnInput) {
    const hexOut = bnInput.toString('hex');
    if (hexOut.length === 64) {
        return hexOut;
    }
    else if (hexOut.length < 64) {
        // pad with leading zeros
        // the padStart function would require node 9
        const padding = '0'.repeat(64 - hexOut.length);
        return `${padding}${hexOut}`;
    }
    else {
        throw new Error('Generated a > 32-byte BN for encryption. Failing.');
    }
}
exports.getHexFromBN = getHexFromBN;
/**
 * Encrypt content to elliptic curve publicKey using ECIES
 * @param {String} publicKey - secp256k1 public key hex string
 * @param {String | Buffer} content - content to encrypt
 * @return {Object} Object containing (hex encoded):
 *  iv (initialization vector), cipherText (cipher text),
 *  mac (message authentication code), ephemeral public key
 *  wasString (boolean indicating with or not to return a buffer or string on decrypt)
 *  @private
 */
function encryptECIES(publicKey, content) {
    return __awaiter(this, void 0, void 0, function* () {
        const isString = (typeof (content) === 'string');
        // always copy to buffer
        const plainText = typeof content === 'string' ? Buffer.from(content) : Buffer.from(content);
        const { getRandomValues, subtle } = yield webCrypto_1.getWebCrypto();
        const ephemeralSK = yield secp256k1_wasm_1.generatePrivateKey();
        const ephemeralPK = yield secp256k1_wasm_1.getPublicKeyFromPrivate(ephemeralSK);
        const decompressedPK = yield secp256k1_wasm_1.decompressPublicKey(publicKey);
        const sharedSecret = yield secp256k1_wasm_1.computeSharedSecret(ephemeralSK, decompressedPK);
        const sharedKeys = yield sharedSecretToKeys(Buffer.from(sharedSecret, 'hex'));
        if (DEBUG_CHECK) {
            const { ec } = yield Promise.resolve().then(() => __importStar(require('elliptic')));
            const ecurveSlow = new ec('secp256k1');
            // const _ephemeralSK = ecurveSlow.genKeyPair()
            const _ephemeralSK = ecurveSlow.keyFromPrivate(Buffer.from(ephemeralSK));
            const _ephemeralPK = _ephemeralSK.getPublic();
            const _ephemeralPKCompressed = Buffer.from(_ephemeralPK.encodeCompressed()).toString('hex');
            const _ecPK = ecurveSlow.keyFromPublic(publicKey, 'hex').getPublic();
            const _ecPK_hex = ecurveSlow.keyFromPublic(publicKey, 'hex').getPublic('hex');
            const _sharedSecret = _ephemeralSK.derive(_ecPK);
            const _sharedSecretHex = getHexFromBN(_sharedSecret);
            assert_1.strict.equal(ephemeralPK, _ephemeralPKCompressed);
            assert_1.strict.equal(decompressedPK, _ecPK_hex);
            assert_1.strict.equal(sharedSecret, _sharedSecretHex);
        }
        const initializationVector = Buffer.alloc(16);
        getRandomValues(initializationVector);
        const cipherText = yield aes256CbcEncrypt(initializationVector, sharedKeys.encryptionKey, plainText);
        const macData = Buffer.concat([initializationVector,
            Buffer.from(ephemeralPK, 'hex'),
            cipherText]);
        const macBytes = yield hmacSha256(sharedKeys.hmacKey, macData);
        const mac = macBytes.toString('hex');
        return {
            iv: initializationVector.toString('hex'),
            ephemeralPK,
            cipherText: cipherText.toString('hex'),
            mac,
            wasString: isString
        };
    });
}
exports.encryptECIES = encryptECIES;
/**
 * Decrypt content encrypted using ECIES
 * @param {String} privateKey - secp256k1 private key hex string
 * @param {Object} cipherObject - object to decrypt, should contain:
 *  iv (initialization vector), cipherText (cipher text),
 *  mac (message authentication code), ephemeralPublicKey
 *  wasString (boolean indicating with or not to return a buffer or string on decrypt)
 * @return {Buffer} plaintext
 * @throws {Error} if unable to decrypt
 * @private
 */
function decryptECIES(privateKey, cipherObject) {
    return __awaiter(this, void 0, void 0, function* () {
        const ephemeralPK = yield secp256k1_wasm_1.decompressPublicKey(cipherObject.ephemeralPK);
        const ephemeralPKCompressed = yield secp256k1_wasm_1.compressPublicKey(ephemeralPK);
        const sharedSecret = yield secp256k1_wasm_1.computeSharedSecret(privateKey, ephemeralPK);
        const sharedSecretBuffer = yield Buffer.from(sharedSecret, 'hex');
        if (DEBUG_CHECK) {
            const { ec } = yield Promise.resolve().then(() => __importStar(require('elliptic')));
            const ecurveSlow = new ec('secp256k1');
            const _ecSK = ecurveSlow.keyFromPrivate(privateKey, 'hex');
            const _ephemeralPK = ecurveSlow.keyFromPublic(cipherObject.ephemeralPK, 'hex').getPublic();
            const _ephemeralPKCompressed = Buffer.from(_ephemeralPK.encodeCompressed()).toString('hex');
            const _sharedSecret = _ecSK.derive(_ephemeralPK);
            const _sharedSecretBuffer = Buffer.from(getHexFromBN(_sharedSecret), 'hex');
            const _sharedSecretHex = _sharedSecretBuffer.toString('hex');
            assert_1.strict.equal(ephemeralPKCompressed, _ephemeralPKCompressed);
            assert_1.strict.equal(sharedSecret, _sharedSecretHex);
        }
        const sharedKeys = yield sharedSecretToKeys(sharedSecretBuffer);
        const ivBuffer = Buffer.from(cipherObject.iv, 'hex');
        const cipherTextBuffer = Buffer.from(cipherObject.cipherText, 'hex');
        const macData = Buffer.concat([ivBuffer,
            Buffer.from(ephemeralPKCompressed, 'hex'),
            cipherTextBuffer]);
        const actualMac = yield hmacSha256(sharedKeys.hmacKey, macData);
        const expectedMac = Buffer.from(cipherObject.mac, 'hex');
        if (!equalConstTime(expectedMac, actualMac)) {
            throw new Error('Decryption failed: failure in MAC check');
        }
        const plainText = yield aes256CbcDecrypt(ivBuffer, sharedKeys.encryptionKey, cipherTextBuffer);
        if (cipherObject.wasString) {
            return plainText.toString();
        }
        else {
            return plainText;
        }
    });
}
exports.decryptECIES = decryptECIES;
/**
 * Sign content using ECDSA
 * @private
 * @param {String} privateKey - secp256k1 private key hex string
 * @param {Object} content - content to sign
 * @return {Object} contains:
 * signature - Hex encoded DER signature
 * public key - Hex encoded private string taken from privateKey
 * @private
 */
function signECDSA(privateKey, content) {
    return __awaiter(this, void 0, void 0, function* () {
        const { subtle } = yield webCrypto_1.getWebCrypto();
        const contentBuffer = typeof content === 'string' ? Buffer.from(content) : content;
        const msgHash = yield subtle.digest('SHA-256', contentBuffer);
        const msgBytes = new Uint8Array(msgHash);
        const publicKey = yield secp256k1_wasm_1.getPublicKeyFromPrivate(privateKey);
        const signature = yield secp256k1_wasm_1.signMessage(privateKey, msgBytes);
        if (DEBUG_CHECK) {
            const nodeCrypto = yield Promise.resolve().then(() => __importStar(require('crypto')));
            const { ec } = yield Promise.resolve().then(() => __importStar(require('elliptic')));
            const ecurveSlow = new ec('secp256k1');
            const fn = yield Promise.resolve().then(() => __importStar(require('../keys')));
            const _publicKey = fn.getPublicKeyFromPrivate(privateKey);
            const _msgHash = nodeCrypto.createHash('sha256').update(contentBuffer).digest();
            const _signature = ecurveSlow.keyFromPrivate(privateKey, 'hex').sign(_msgHash).toDER('hex');
            const _hashHex = Buffer.from(_msgHash).toString('hex');
            const hashHex = Buffer.from(msgHash).toString('hex');
            assert_1.strict.equal(publicKey, _publicKey);
            assert_1.strict.equal(hashHex, _hashHex);
            assert_1.strict.equal(signature, _signature);
        }
        return {
            signature,
            publicKey
        };
    });
}
exports.signECDSA = signECDSA;
/**
 * Verify content using ECDSA
 * @param {String | Buffer} content - Content to verify was signed
 * @param {String} publicKey - secp256k1 private key hex string
 * @param {String} signature - Hex encoded DER signature
 * @return {Boolean} returns true when signature matches publickey + content, false if not
 * @private
 */
function verifyECDSA(content, publicKey, signature) {
    return __awaiter(this, void 0, void 0, function* () {
        const { subtle } = yield webCrypto_1.getWebCrypto();
        const contentBuffer = typeof content === 'string' ? Buffer.from(content) : content;
        const contentHash = yield subtle.digest('SHA-256', contentBuffer);
        const contentBytes = new Uint8Array(contentHash);
        const verified = yield secp256k1_wasm_1.verifyMessage(signature, publicKey, contentBytes);
        if (DEBUG_CHECK) {
            const nodeCrypto = yield Promise.resolve().then(() => __importStar(require('crypto')));
            const { ec } = yield Promise.resolve().then(() => __importStar(require('elliptic')));
            const ecurveSlow = new ec('secp256k1');
            const _contentHash = nodeCrypto.createHash('sha256').update(contentBuffer).digest();
            const _verified = ecurveSlow.keyFromPublic(publicKey, 'hex').verify(_contentHash, signature);
            const _hashHex = Buffer.from(_contentHash).toString('hex');
            const hashHex = Buffer.from(contentBytes).toString('hex');
            assert_1.strict.equal(hashHex, _hashHex);
            assert_1.strict.equal(verified, _verified);
        }
        return verified;
    });
}
exports.verifyECDSA = verifyECDSA;
//# sourceMappingURL=ecFast.js.map