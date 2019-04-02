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
const hub_1 = require("./hub");
exports.connectToGaiaHub = hub_1.connectToGaiaHub;
exports.uploadToGaiaHub = hub_1.uploadToGaiaHub;
exports.BLOCKSTACK_GAIA_HUB_LABEL = hub_1.BLOCKSTACK_GAIA_HUB_LABEL;
// export { type GaiaHubConfig } from './hub'
const ecFast_1 = require("../encryption/ecFast");
const keys_1 = require("../keys");
const profileLookup_1 = require("../profiles/profileLookup");
const errors_1 = require("../errors");
const logger_1 = require("../logger");
const userSession_1 = require("../auth/userSession");
const SIGNATURE_FILE_SUFFIX = '.sig';
/**
 * Deletes the specified file from the app's data store. Currently not implemented.
 * @param {String} path - the path to the file to delete
 * @returns {Promise} that resolves when the file has been removed
 * or rejects with an error
 */
function deleteFile(path) {
    Promise.reject(new Error(`Delete of ${path} not supported by gaia hubs`));
}
exports.deleteFile = deleteFile;
/**
 * Fetch the public read URL of a user file for the specified app.
 * @param {String} path - the path to the file to read
 * @param {String} username - The Blockstack ID of the user to look up
 * @param {String} appOrigin - The app origin
 * @param {String} [zoneFileLookupURL=null] - The URL
 * to use for zonefile lookup. If falsey, this will use the
 * blockstack.js's getNameInfo function instead.
 * @return {Promise<string>} that resolves to the public read URL of the file
 * or rejects with an error
 */
function getUserAppFileUrl(path, username, appOrigin, zoneFileLookupURL) {
    return __awaiter(this, void 0, void 0, function* () {
        const profile = yield profileLookup_1.lookupProfile(username, zoneFileLookupURL);
        let bucketUrl = null;
        if (profile.hasOwnProperty('apps')) {
            if (profile.apps.hasOwnProperty(appOrigin)) {
                const url = profile.apps[appOrigin];
                const bucket = url.replace(/\/?(\?|#|$)/, '/$1');
                bucketUrl = `${bucket}${path}`;
            }
        }
        return bucketUrl;
    });
}
exports.getUserAppFileUrl = getUserAppFileUrl;
/**
 * Encrypts the data provided with the app public key.
 * @param {String|Buffer} content - data to encrypt
 * @param {Object} [options=null] - options object
 * @param {String} options.publicKey - the hex string of the ECDSA public
 * key to use for encryption. If not provided, will use user's appPublicKey.
 * @return {String} Stringified ciphertext object
 */
function encryptContent(content, options, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const opts = Object.assign({}, options);
        if (!opts.publicKey) {
            const privateKey = (caller || new userSession_1.UserSession()).loadUserData().appPrivateKey;
            opts.publicKey = keys_1.getPublicKeyFromPrivate(privateKey);
        }
        const cipherObject = yield ecFast_1.encryptECIES(opts.publicKey, content);
        return JSON.stringify(cipherObject);
    });
}
exports.encryptContent = encryptContent;
/**
 * Decrypts data encrypted with `encryptContent` with the
 * transit private key.
 * @param {String|Buffer} content - encrypted content.
 * @param {Object} [options=null] - options object
 * @param {String} options.privateKey - the hex string of the ECDSA private
 * key to use for decryption. If not provided, will use user's appPrivateKey.
 * @return {String|Buffer} decrypted content.
 */
function decryptContent(content, options, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const opts = Object.assign({}, options);
        if (!opts.privateKey) {
            opts.privateKey = (caller || new userSession_1.UserSession()).loadUserData().appPrivateKey;
        }
        try {
            const cipherObject = JSON.parse(content);
            return yield ecFast_1.decryptECIES(opts.privateKey, cipherObject);
        }
        catch (err) {
            if (err instanceof SyntaxError) {
                throw new Error('Failed to parse encrypted content JSON. The content may not '
                    + 'be encrypted. If using getFile, try passing { decrypt: false }.');
            }
            else {
                throw err;
            }
        }
    });
}
exports.decryptContent = decryptContent;
/* Get the gaia address used for servicing multiplayer reads for the given
 * (username, app) pair.
 * @private
 */
function getGaiaAddress(app, username, zoneFileLookupURL, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const opts = normalizeOptions({ app, username }, caller);
        let fileUrl;
        if (username) {
            fileUrl = yield getUserAppFileUrl('/', opts.username, opts.app, zoneFileLookupURL);
        }
        else {
            if (!caller) {
                caller = new userSession_1.UserSession();
            }
            const gaiaHubConfig = yield caller.getOrSetLocalGaiaHubConnection();
            fileUrl = yield hub_1.getFullReadUrl('/', gaiaHubConfig);
        }
        const matches = fileUrl.match(/([13][a-km-zA-HJ-NP-Z0-9]{26,35})/);
        if (!matches) {
            throw new Error('Failed to parse gaia address');
        }
        return matches[matches.length - 1];
    });
}
/**
 * @param {Object} [options=null] - options object
 * @param {String} options.username - the Blockstack ID to lookup for multi-player storage
 * @param {String} options.app - the app to lookup for multi-player storage -
 * defaults to current origin
 */
function normalizeOptions(options, caller) {
    const opts = Object.assign({}, options);
    if (opts.username) {
        if (!opts.app) {
            const appConfig = (caller || new userSession_1.UserSession()).appConfig;
            if (!appConfig) {
                throw new errors_1.InvalidStateError('Missing AppConfig');
            }
            opts.app = appConfig.appDomain;
        }
    }
    return opts;
}
/**
 * Get the URL for reading a file from an app's data store.
 * @param {String} path - the path to the file to read
 * @param {Object} [options=null] - options object
 * @param {String} options.username - the Blockstack ID to lookup for multi-player storage
 * @param {String} options.app - the app to lookup for multi-player storage -
 * defaults to current origin
 * @param {String} [options.zoneFileLookupURL=null] - The URL
 * to use for zonefile lookup. If falsey, this will use the
 * blockstack.js's getNameInfo function instead.
 * @returns {Promise<string>} that resolves to the URL or rejects with an error
 */
function getFileUrl(path, options, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const opts = normalizeOptions(options, caller);
        let readUrl;
        if (opts.username) {
            readUrl = yield getUserAppFileUrl(path, opts.username, opts.app, opts.zoneFileLookupURL);
        }
        else {
            const gaiaHubConfig = yield (caller || new userSession_1.UserSession()).getOrSetLocalGaiaHubConnection();
            readUrl = yield hub_1.getFullReadUrl(path, gaiaHubConfig);
        }
        if (!readUrl) {
            throw new Error('Missing readURL');
        }
        else {
            return readUrl;
        }
    });
}
exports.getFileUrl = getFileUrl;
/* Handle fetching the contents from a given path. Handles both
 *  multi-player reads and reads from own storage.
 * @private
 */
function getFileContents(path, app, username, zoneFileLookupURL, forceText, caller) {
    return Promise.resolve()
        .then(() => {
        const opts = { app, username, zoneFileLookupURL };
        return getFileUrl(path, opts, caller);
    })
        .then(readUrl => fetch(readUrl))
        .then((response) => {
        if (response.status !== 200) {
            if (response.status === 404) {
                logger_1.Logger.debug(`getFile ${path} returned 404, returning null`);
                return null;
            }
            else {
                throw new Error(`getFile ${path} failed with HTTP status ${response.status}`);
            }
        }
        const contentType = response.headers.get('Content-Type');
        if (forceText || contentType === null
            || contentType.startsWith('text')
            || contentType === 'application/json') {
            return response.text();
        }
        else {
            return response.arrayBuffer().then((arr) => Buffer.from(arr));
        }
    });
}
/* Handle fetching an unencrypted file, its associated signature
 *  and then validate it. Handles both multi-player reads and reads
 *  from own storage.
 * @private
 */
function getFileSignedUnencrypted(path, opt, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        // future optimization note:
        //    in the case of _multi-player_ reads, this does a lot of excess
        //    profile lookups to figure out where to read files
        //    do browsers cache all these requests if Content-Cache is set?
        const [fileContents, signatureContents, gaiaAddress] = yield Promise.all([getFileContents(path, opt.app, opt.username, opt.zoneFileLookupURL, false, caller),
            getFileContents(`${path}${SIGNATURE_FILE_SUFFIX}`, opt.app, opt.username, opt.zoneFileLookupURL, true, caller),
            getGaiaAddress(opt.app, opt.username, opt.zoneFileLookupURL, caller)]);
        if (!fileContents) {
            return fileContents;
        }
        if (!gaiaAddress) {
            throw new errors_1.SignatureVerificationError('Failed to get gaia address for verification of: '
                + `${path}`);
        }
        if (!signatureContents || typeof signatureContents !== 'string') {
            throw new errors_1.SignatureVerificationError('Failed to obtain signature for file: '
                + `${path} -- looked in ${path}${SIGNATURE_FILE_SUFFIX}`);
        }
        let signature;
        let publicKey;
        try {
            const sigObject = JSON.parse(signatureContents);
            signature = sigObject.signature;
            publicKey = sigObject.publicKey;
        }
        catch (err) {
            if (err instanceof SyntaxError) {
                throw new Error('Failed to parse signature content JSON '
                    + `(path: ${path}${SIGNATURE_FILE_SUFFIX})`
                    + ' The content may be corrupted.');
            }
            else {
                throw err;
            }
        }
        const signerAddress = keys_1.publicKeyToAddress(publicKey);
        if (gaiaAddress !== signerAddress) {
            throw new errors_1.SignatureVerificationError(`Signer pubkey address (${signerAddress}) doesn't`
                + ` match gaia address (${gaiaAddress})`);
        }
        else if (!(yield ecFast_1.verifyECDSA(fileContents, publicKey, signature))) {
            throw new errors_1.SignatureVerificationError('Contents do not match ECDSA signature: '
                + `path: ${path}, signature: ${path}${SIGNATURE_FILE_SUFFIX}`);
        }
        else {
            return fileContents;
        }
    });
}
/* Handle signature verification and decryption for contents which are
 *  expected to be signed and encrypted. This works for single and
 *  multiplayer reads. In the case of multiplayer reads, it uses the
 *  gaia address for verification of the claimed public key.
 * @private
 */
function handleSignedEncryptedContents(caller, path, storedContents, app, username, zoneFileLookupURL) {
    return __awaiter(this, void 0, void 0, function* () {
        const appPrivateKey = caller.loadUserData().appPrivateKey;
        const appPublicKey = keys_1.getPublicKeyFromPrivate(appPrivateKey);
        let address;
        if (username) {
            address = yield getGaiaAddress(app, username, zoneFileLookupURL, caller);
        }
        else {
            address = yield keys_1.publicKeyToAddress(appPublicKey);
        }
        if (!address) {
            throw new errors_1.SignatureVerificationError('Failed to get gaia address for verification of: '
                + `${path}`);
        }
        let sigObject;
        try {
            sigObject = JSON.parse(storedContents);
        }
        catch (err) {
            if (err instanceof SyntaxError) {
                throw new Error('Failed to parse encrypted, signed content JSON. The content may not '
                    + 'be encrypted. If using getFile, try passing'
                    + ' { verify: false, decrypt: false }.');
            }
            else {
                throw err;
            }
        }
        const signature = sigObject.signature;
        const signerPublicKey = sigObject.publicKey;
        const cipherText = sigObject.cipherText;
        const signerAddress = keys_1.publicKeyToAddress(signerPublicKey);
        if (!signerPublicKey || !cipherText || !signature) {
            throw new errors_1.SignatureVerificationError('Failed to get signature verification data from file:'
                + ` ${path}`);
        }
        else if (signerAddress !== address) {
            throw new errors_1.SignatureVerificationError(`Signer pubkey address (${signerAddress}) doesn't`
                + ` match gaia address (${address})`);
        }
        else if (!(yield ecFast_1.verifyECDSA(cipherText, signerPublicKey, signature))) {
            throw new errors_1.SignatureVerificationError('Contents do not match ECDSA signature in file:'
                + ` ${path}`);
        }
        else {
            return caller.decryptContent(cipherText);
        }
    });
}
/**
 * Retrieves the specified file from the app's data store.
 * @param {String} path - the path to the file to read
 * @param {Object} [options=null] - options object
 * @param {Boolean} [options.decrypt=true] - try to decrypt the data with the app private key
 * @param {String} options.username - the Blockstack ID to lookup for multi-player storage
 * @param {Boolean} options.verify - Whether the content should be verified, only to be used
 * when `putFile` was set to `sign = true`
 * @param {String} options.app - the app to lookup for multi-player storage -
 * defaults to current origin
 * @param {String} [options.zoneFileLookupURL=null] - The URL
 * to use for zonefile lookup. If falsey, this will use the
 * blockstack.js's getNameInfo function instead.
 * @returns {Promise} that resolves to the raw data in the file
 * or rejects with an error
 */
function getFile(path, options, caller) {
    const defaults = {
        decrypt: true,
        verify: false,
        username: null,
        app: typeof window !== 'undefined' ? window.location.origin : undefined,
        zoneFileLookupURL: null
    };
    const opt = Object.assign({}, defaults, options);
    if (!caller) {
        caller = new userSession_1.UserSession();
    }
    // in the case of signature verification, but no
    //  encryption expected, need to fetch _two_ files.
    if (opt.verify && !opt.decrypt) {
        return getFileSignedUnencrypted(path, opt, caller);
    }
    return getFileContents(path, opt.app, opt.username, opt.zoneFileLookupURL, !!opt.decrypt, caller)
        .then((storedContents) => {
        if (storedContents === null) {
            return storedContents;
        }
        else if (opt.decrypt && !opt.verify) {
            if (typeof storedContents !== 'string') {
                throw new Error('Expected to get back a string for the cipherText');
            }
            return caller.decryptContent(storedContents);
        }
        else if (opt.decrypt && opt.verify) {
            if (typeof storedContents !== 'string') {
                throw new Error('Expected to get back a string for the cipherText');
            }
            return handleSignedEncryptedContents(caller, path, storedContents, opt.app, opt.username, opt.zoneFileLookupURL);
        }
        else if (!opt.verify && !opt.decrypt) {
            return storedContents;
        }
        else {
            throw new Error('Should be unreachable.');
        }
    });
}
exports.getFile = getFile;
function readBlob(blob) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onerror = () => {
                reader.abort();
                reject(reader.error || 'failed to read blob');
            };
            reader.onload = () => {
                const buffer = new Uint8Array(reader.result);
                resolve(buffer);
            };
            reader.readAsDataURL(blob);
        });
    });
}
/**
 * Stores the data provided in the app's data store to to the file specified.
 * @param {String} path - the path to store the data in
 * @param {String|Buffer} content - the data to store in the file
 * @param {Object} [options=null] - options object
 * @param {Boolean|String} [options.encrypt=true] - encrypt the data with the app public key
 *                                                  or the provided public key
 * @param {Boolean} [options.sign=false] - sign the data using ECDSA on SHA256 hashes with
 *                                         the app private key
 * @param {String} [options.contentType=''] - set a Content-Type header for unencrypted data
 * @return {Promise} that resolves if the operation succeed and rejects
 * if it failed
 */
function putFile(path, content, options, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const defaults = {
            encrypt: true,
            sign: false,
            contentType: ''
        };
        if (typeof File !== 'undefined' && content instanceof File) {
            defaults.contentType = content.type;
        }
        const opt = Object.assign({}, defaults, options);
        let { contentType } = opt;
        if (!contentType) {
            contentType = (typeof (content) === 'string') ? 'text/plain; charset=utf-8' : 'application/octet-stream';
        }
        if (!caller) {
            caller = new userSession_1.UserSession();
        }
        if (typeof Blob !== 'undefined' && content instanceof Blob) {
            content = yield readBlob(content);
        }
        content = content;
        // First, let's figure out if we need to get public/private keys,
        //  or if they were passed in
        let privateKey = '';
        let publicKey = '';
        if (opt.sign) {
            if (typeof (opt.sign) === 'string') {
                privateKey = opt.sign;
            }
            else {
                privateKey = caller.loadUserData().appPrivateKey;
            }
        }
        if (opt.encrypt) {
            if (typeof (opt.encrypt) === 'string') {
                publicKey = opt.encrypt;
            }
            else {
                if (!privateKey) {
                    privateKey = caller.loadUserData().appPrivateKey;
                }
                publicKey = keys_1.getPublicKeyFromPrivate(privateKey);
            }
        }
        // In the case of signing, but *not* encrypting,
        //   we perform two uploads. So the control-flow
        //   here will return there.
        if (!opt.encrypt && opt.sign) {
            const signatureObject = yield ecFast_1.signECDSA(privateKey, content);
            const signatureContent = JSON.stringify(signatureObject);
            const gaiaHubConfig = yield caller.getOrSetLocalGaiaHubConnection();
            try {
                const fileUrls = yield Promise.all([
                    hub_1.uploadToGaiaHub(path, content, gaiaHubConfig, contentType),
                    hub_1.uploadToGaiaHub(`${path}${SIGNATURE_FILE_SUFFIX}`, signatureContent, gaiaHubConfig, 'application/json')
                ]);
                return fileUrls[0];
            }
            catch (error) {
                const freshHubConfig = yield caller.setLocalGaiaHubConnection();
                const fileUrls = yield Promise.all([
                    hub_1.uploadToGaiaHub(path, content, freshHubConfig, contentType),
                    hub_1.uploadToGaiaHub(`${path}${SIGNATURE_FILE_SUFFIX}`, signatureContent, freshHubConfig, 'application/json')
                ]);
                return fileUrls[0];
            }
        }
        // In all other cases, we only need one upload.
        if (opt.encrypt && !opt.sign) {
            content = yield encryptContent(content, { publicKey });
            contentType = 'application/json';
        }
        else if (opt.encrypt && opt.sign) {
            const cipherText = yield encryptContent(content, { publicKey });
            const signatureObject = yield ecFast_1.signECDSA(privateKey, cipherText);
            const signedCipherObject = {
                signature: signatureObject.signature,
                publicKey: signatureObject.publicKey,
                cipherText
            };
            content = JSON.stringify(signedCipherObject);
            contentType = 'application/json';
        }
        const gaiaHubConfig = yield caller.getOrSetLocalGaiaHubConnection();
        try {
            return yield hub_1.uploadToGaiaHub(path, content, gaiaHubConfig, contentType);
        }
        catch (error) {
            const freshHubConfig = yield caller.setLocalGaiaHubConnection();
            const file = yield hub_1.uploadToGaiaHub(path, content, freshHubConfig, contentType);
            return file;
        }
    });
}
exports.putFile = putFile;
/**
 * Get the app storage bucket URL
 * @param {String} gaiaHubUrl - the gaia hub URL
 * @param {String} appPrivateKey - the app private key used to generate the app address
 * @returns {Promise} That resolves to the URL of the app index file
 * or rejects if it fails
 */
function getAppBucketUrl(gaiaHubUrl, appPrivateKey) {
    return hub_1.getBucketUrl(gaiaHubUrl, appPrivateKey);
}
exports.getAppBucketUrl = getAppBucketUrl;
/**
 * Loop over the list of files in a Gaia hub, and run a callback on each entry.
 * Not meant to be called by external clients.
 * @param {GaiaHubConfig} hubConfig - the Gaia hub config
 * @param {String | null} page - the page ID
 * @param {number} callCount - the loop count
 * @param {number} fileCount - the number of files listed so far
 * @param {function} callback - the callback to invoke on each file.  If it returns a falsey
 *  value, then the loop stops.  If it returns a truthy value, the loop continues.
 * @returns {Promise} that resolves to the number of files listed.
 * @private
 */
function listFilesLoop(hubConfig, page, callCount, fileCount, callback) {
    if (callCount > 65536) {
        // this is ridiculously huge, and probably indicates
        // a faulty Gaia hub anyway (e.g. on that serves endless data)
        throw new Error('Too many entries to list');
    }
    let httpStatus;
    const pageRequest = JSON.stringify({ page });
    const fetchOptions = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': `${pageRequest.length}`,
            Authorization: `bearer ${hubConfig.token}`
        },
        body: pageRequest
    };
    return fetch(`${hubConfig.server}/list-files/${hubConfig.address}`, fetchOptions)
        .then((response) => {
        httpStatus = response.status;
        if (httpStatus >= 400) {
            throw new Error(`listFiles failed with HTTP status ${httpStatus}`);
        }
        return response.text();
    })
        .then(responseText => JSON.parse(responseText))
        .then((responseJSON) => {
        const entries = responseJSON.entries;
        const nextPage = responseJSON.page;
        if (entries === null || entries === undefined) {
            // indicates a misbehaving Gaia hub or a misbehaving driver
            // (i.e. the data is malformed)
            throw new Error('Bad listFiles response: no entries');
        }
        for (let i = 0; i < entries.length; i++) {
            const rc = callback(entries[i]);
            if (!rc) {
                // callback indicates that we're done
                return Promise.resolve(fileCount + i);
            }
        }
        if (nextPage && entries.length > 0) {
            // keep going -- have more entries
            return listFilesLoop(hubConfig, nextPage, callCount + 1, fileCount + entries.length, callback);
        }
        else {
            // no more entries -- end of data
            return Promise.resolve(fileCount + entries.length);
        }
    });
}
/**
 * List the set of files in this application's Gaia storage bucket.
 * @param {UserSession} caller - instance calling this method
 * @param {function} callback - a callback to invoke on each named file that
 * returns `true` to continue the listing operation or `false` to end it
 * @return {Promise} that resolves to the number of files listed
 */
function listFiles(callback, caller) {
    return __awaiter(this, void 0, void 0, function* () {
        const userSession = caller || new userSession_1.UserSession();
        const gaiaHubConfig = yield userSession.getOrSetLocalGaiaHubConnection();
        return listFilesLoop(gaiaHubConfig, null, 0, 0, callback);
    });
}
exports.listFiles = listFiles;
//# sourceMappingURL=index.js.map