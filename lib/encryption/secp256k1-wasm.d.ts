/// <reference types="node" />
/**
 * @param privateKey hex string or buffer
 * @returns hex string
 */
export declare function getPublicKeyFromPrivate(privateKey: string | Buffer | Uint8Array, compressed?: boolean): Promise<string>;
export declare function compressPublicKey(publicKey: string | Buffer | Uint8Array): Promise<string>;
export declare function decompressPublicKey(publicKey: string | Buffer | Uint8Array): Promise<string>;
export declare function signMessage(privateKey: string | Buffer | Uint8Array, message: Buffer | Uint8Array): Promise<string>;
export declare function verifyMessage(signature: string | Buffer | Uint8Array, publicKey: string | Buffer | Uint8Array, messageHash: Buffer | Uint8Array): Promise<boolean>;
export declare function generatePrivateKey(): Promise<Buffer | Uint8Array>;
export declare function computeSharedSecret(privateKey: string | Buffer | Uint8Array, publicKey: string | Buffer | Uint8Array): Promise<string>;
