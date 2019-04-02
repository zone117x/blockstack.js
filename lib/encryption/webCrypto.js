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
let webCryptoCached = null;
function getWebCrypto() {
    return __awaiter(this, void 0, void 0, function* () {
        if (typeof self !== 'undefined' && self.crypto && self.crypto.subtle) {
            // TODO: ensure our usage of WebCrypto API works in all browsers we support,
            // otherwise we may need https://www.npmjs.com/package/webcrypto-liner
            return self.crypto;
        }
        else {
            if (webCryptoCached === null) {
                webCryptoCached = (() => __awaiter(this, void 0, void 0, function* () {
                    try {
                        const { default: WebCrypto } = yield Promise.resolve().then(() => __importStar(require('node-webcrypto-ossl')));
                        const webCryptoInstance = new WebCrypto();
                        return webCryptoInstance;
                    }
                    catch (error) {
                        console.error('The WebCrypto API is not available in this environment, '
                            + 'and the `node-webcrypto-ossl` module could not be imported. If running '
                            + 'within Node environment then ensure the `node-webcrypto-ossl` peer '
                            + 'dependency is installed.');
                        throw error;
                    }
                }))();
            }
            return webCryptoCached;
        }
    });
}
exports.getWebCrypto = getWebCrypto;
//# sourceMappingURL=webCrypto.js.map