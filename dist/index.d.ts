/// <reference types="node" />
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
    (err: Error | null, password: string, salt: string, hash: string): void;
}
interface IHasher {
    (opts: IOptions, callback: IHasherCallback): void;
}
export default function build(options?: GenerateOption): IHasher;
export {};
