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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var node_crypto_1 = __importDefault(require("node:crypto"));
var fastfall_ts_1 = __importDefault(require("fastfall-ts"));
//const cryto = require('crypto');
// const fastfall = require('fastfall');
// we can support a digest if we are not in node v0.10
var supportsDigest = process.version.indexOf('v0.10') !== 0;
function build(options) {
    var saltLength = options ? options.saltLength : 64;
    var iterations = options ? options.iterations : 10000;
    var keyLength = options ? options.keyLength : 128;
    var digest = options ? options.digest : 'sha1';
    var genHash = supportsDigest ? genHashWithDigest : genHashWithoutDigest;
    if (digest !== 'sha1' && !supportsDigest) {
        throw new Error('v0.10 does not support setting a digest');
    }
    var passNeeded = (0, fastfall_ts_1.default)([genPass, genSalt, genHash], [function () { }]);
    var saltNeeded = (0, fastfall_ts_1.default)([genSalt, genHash], [function () { }]);
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
    var hasher = function (opts, callback) {
        if (typeof opts.password !== 'string') {
            passNeeded(opts, callback);
        }
        else if (typeof opts.salt !== 'string') {
            saltNeeded(opts, callback);
        }
        else {
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
    function genPass(opts, cb) {
        // generate a 10-bytes password
        var err = null;
        try {
            var buffer = node_crypto_1.default.randomBytes(10);
            opts.password = buffer.toString('base64');
        }
        catch (e) {
            err = e;
        }
        finally {
            cb(err, opts);
        }
    }
    /**
     * Generates a new salt
     *
     * @api private
     * @param {Object} opts The options (where the new password will be stored)
     * @param {Function} cb The callback
     */
    function genSalt(opts, cb) {
        var err = null;
        try {
            var buffer = node_crypto_1.default.randomBytes(saltLength);
            opts.salt = buffer;
        }
        catch (e) {
            err = e;
        }
        finally {
            cb(err, opts);
        }
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
    function genHashWithDigest(opts, cb) {
        node_crypto_1.default.pbkdf2(opts.password, opts.salt, iterations, keyLength, digest, function (err, hash) {
            if (typeof hash === 'string') {
                hash = Buffer.from(hash, 'binary');
            }
            cb(err, opts.password, opts.salt.toString('base64'), hash.toString('base64'));
        });
        // cryto.pbkdf2(
        //     opts.password,
        //     opts.salt,
        //     iterations,
        //     keyLength,
        //     digest,
        //     function (err: Error, hash: string | Buffer) {
        //         if (typeof hash === 'string') {
        //             hash = Buffer.from(hash, 'binary');
        //         }
        //         cb(err, opts.password, opts.salt.toString('base64'), hash.toString('base64'));
        //     },
        // );
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
    function genHashWithoutDigest(opts, cb) {
        node_crypto_1.default.pbkdf2(opts.password, opts.salt, iterations, keyLength, digest, function (err, hash) {
            if (typeof hash === 'string') {
                hash = Buffer.from(hash, 'binary');
            }
            cb(err, opts.password, opts.salt.toString('base64'), hash.toString('base64'));
        });
    }
    return hasher;
}
exports.default = build;
