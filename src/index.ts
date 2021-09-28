/*
Copyright (c) 2013-2016 Matteo Collina, http://matteocollina.com

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
'use strict';
const cryto = require('crypto');
const fastfall = require('fastfall');

// we can support a digest if we are not in node v0.10
const supportsDigest = process.version.indexOf('v0.10') !== 0;

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

module.exports = function build(options?: GenerateOption): IHasher {
    const saltLength = options ? options.saltLength : 64;
    const iterations = options ? options.iterations : 10000;
    const keyLength = options ? options.keyLength : 128;
    const digest = options ? options.digest : 'sha1';
    const genHash = supportsDigest ? genHashWithDigest : genHashWithoutDigest;

    if (digest !== 'sha1' && !supportsDigest) {
        throw new Error('v0.10 does not support setting a digest');
    }

    const passNeeded = fastfall([genPass, genSalt, genHash]);

    const saltNeeded = fastfall([genSalt, genHash]);

    /**
     * Hash a password, using a hash and the pbkd2
     * crypto module.
     *
     * Options:
     *  - `password`, the password to hash.
     *  - `salt`, the salt to use, as a base64 string.
     *
     *  If the `password` is left undefined, a new
     *  10-bytes password will be generated, and converted
     *  to base64.
     *
     *  If the `salt` is left undefined, a new salt is generated.
     *
     *  The callback will be called with the following arguments:
     *   - the error, if something when wrong.
     *   - the password.
     *   - the salt, encoded in base64.
     *   - the hash, encoded in base64.
     *
     * @param {Object} opts The options (optional)
     * @param {Function} callback
     */
    const hasher: IHasher = (opts, callback) => {
        if (typeof opts.password !== 'string') {
            passNeeded(opts, callback);
        } else if (typeof opts.salt !== 'string') {
            saltNeeded(opts, callback);
        } else {
            opts.salt = Buffer.from(opts.salt, 'base64');
            genHash(opts, callback);
        }
    };

    /**
     * Generates a new password
     *
     * @api private
     * @param {Object} opts The options (where the new password will be stored)
     * @param {Function} cb The callback
     */
    function genPass(opts: IOptions, cb: Function) {
        // generate a 10-bytes password
        cryto.randomBytes(10, function (err: Error, buffer: Buffer) {
            if (buffer) {
                opts.password = buffer.toString('base64');
            }
            cb(err, opts);
        });
    }

    /**
     * Generates a new salt
     *
     * @api private
     * @param {Object} opts The options (where the new password will be stored)
     * @param {Function} cb The callback
     */
    function genSalt(opts: IOptions, cb: Function) {
        cryto.randomBytes(saltLength, function (err: Error, buf: Buffer) {
            opts.salt = buf;
            cb(err, opts);
        });
    }

    /**
     * Generates a new hash using the password and the salt
     *
     *  The callback will be called with the following arguments:
     *   - the error, if something when wrong.
     *   - the password.
     *   - the salt, encoded in base64.
     *   - the hash, encoded in base64.
     *
     * @api private
     * @param {Object} opts The options used to generate the hash (password & salt)
     * @param {Function} cb The callback
     */
    function genHashWithDigest(opts: IOptions, cb: Function) {
        cryto.pbkdf2(
            opts.password,
            opts.salt,
            iterations,
            keyLength,
            digest,
            function (err: Error, hash: string | Buffer) {
                if (typeof hash === 'string') {
                    hash = Buffer.from(hash, 'binary');
                }

                cb(err, opts.password, opts.salt.toString('base64'), hash.toString('base64'));
            },
        );
    }

    /**
     * Generates a new hash using the password and the salt
     *
     *  The callback will be called with the following arguments:
     *   - the error, if something when wrong.
     *   - the password.
     *   - the salt, encoded in base64.
     *   - the hash, encoded in base64.
     *
     * @api private
     * @param {Object} opts The options used to generate the hash (password & salt)
     * @param {Function} cb The callback
     */
    function genHashWithoutDigest(opts: IOptions, cb: IHasherCallback) {
        cryto.pbkdf2(opts.password, opts.salt, iterations, keyLength, function (err: Error, hash: string | Buffer) {
            if (typeof hash === 'string') {
                hash = Buffer.from(hash, 'binary');
            }

            cb(err, opts.password, opts.salt.toString('base64'), hash.toString('base64'));
        });
    }

    return hasher;
};
