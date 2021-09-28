/// <reference types="node" />
declare const cryto: any;
declare const fastfall: any;
declare const supportsDigest: boolean;
/**
 * Creates a new password hasher
 *
 * options:
 *  - `saltLength`, the length of the random salt
 *  - `iterations`, number of pbkdf2 iterations
 *  - `keyLength`, the length of the generated keys
 *  - `digest`, the digest algorithm, default 'sha1'
 */
interface GenerateOption {
    saltLength: number;
    iterations: number;
    keyLength: number;
    digest: string;
}
interface IOptions {
    password: string;
    salt: string | Buffer;
}
interface IHasherCallback {
    (err: Error, password: string, salt: string, hash: string): void;
}
interface IHasher {
    (opts: IOptions, callback: IHasherCallback): void;
}
