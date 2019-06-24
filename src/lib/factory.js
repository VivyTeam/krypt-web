import scrypt from "scrypt-async";

export default algorithm => {
  const types = ["aes-gcm", "rsa-oaep", "aes-cbc", "scrypt"];
  const algorithmType = algorithm.toLowerCase();

  switch (algorithmType) {
    case "aes-gcm":
      return {
        /**
         * @private
         * @returns {PromiseLike<CryptoKey>}
         */
        generateKey: () =>
          window.crypto.subtle.generateKey(
            {
              name: "AES-GCM",
              length: 256
            },
            true,
            ["encrypt", "decrypt"]
          ),
        /**
         * @private
         * @param key {arrayBuffer}
         * @returns {PromiseLike<CryptoKey>}
         */
        importKey: key =>
          window.crypto.subtle.importKey(
            "raw",
            key,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
          ),
        /**
         * @private
         * @param key {CryptoKey}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        exportKey: key => window.crypto.subtle.exportKey("raw", key),
        /**
         * @private
         * @param key {CryptoKey}
         * @param iv {arrayBuffer}
         * @param data {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        encrypt: (key, iv, data) =>
          window.crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv
            },
            key,
            data
          ),
        /**
         * @private
         * @param key {CryptoKey}
         * @param iv {arrayBuffer}
         * @param data {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        decrypt: (key, iv, data) =>
          window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv: new Uint8Array(iv)
            },
            key,
            data
          )
      };
    case "rsa-oaep":
      return {
        /**
         * @private
         * @param bits {number}
         * @returns {PromiseLike<CryptoKeyPair>}
         */
        generateKey: (bits = 4096) =>
          window.crypto.subtle.generateKey(
            {
              name: "RSA-OAEP",
              modulusLength: bits,
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
              hash: { name: "SHA-256" }
            },
            false,
            ["encrypt", "decrypt"]
          ),
        /**
         * @private
         * @param key {arrayBuffer}
         * @returns {PromiseLike<CryptoKey>}
         */
        importKey: key =>
          window.crypto.subtle.importKey(
            "spki",
            key,
            { name: "RSA-OAEP", hash: { name: "SHA-256" } },
            false,
            ["encrypt"]
          ),
        /**
         * @private
         * @param publicKey {CryptoKey}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        exportKey: publicKey =>
          window.crypto.subtle.exportKey("spki", publicKey),
        /**
         * @private
         * @param publicKey {CryptoKey}
         * @param buffer {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        encrypt: (publicKey, buffer) =>
          window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, buffer),
        /**
         * @private
         * @param privateKey {CryptoKey}
         * @param arrayBuffer {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        decrypt: (privateKey, arrayBuffer) =>
          window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            arrayBuffer
          )
      };
    case "aes-cbc":
      return {
        /**
         * @private
         * @returns {PromiseLike<CryptoKey>}
         */
        generateKey: () =>
          window.crypto.subtle.generateKey(
            {
              name: "AES-CBC",
              length: 256
            },
            true,
            ["encrypt", "decrypt"]
          ),
        /**
         * @private
         * @param key {arrayBuffer}
         * @returns {PromiseLike<CryptoKey>}
         */
        importKey: key =>
          window.crypto.subtle.importKey(
            "raw",
            key,
            { name: "AES-CBC" },
            false,
            ["encrypt", "decrypt"]
          ),
        /**
         * @private
         * @param key {CryptoKey}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        exportKey: key => window.crypto.subtle.exportKey("raw", key),
        /**
         * @private
         * @param key {CryptoKey}
         * @param iv {arrayBuffer}
         * @param data {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        encrypt: (key, iv, data) =>
          window.crypto.subtle.encrypt(
            {
              name: "AES-CBC",
              iv
            },
            key,
            data
          ),
        /**
         * @private
         * @param key {CryptoKey}
         * @param iv {arrayBuffer}
         * @param data {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        decrypt: (key, iv, data) =>
          window.crypto.subtle.decrypt(
            {
              name: "AES-CBC",
              iv: new Uint8Array(iv)
            },
            key,
            data
          )
      };
    case "scrypt":
      return {
        /**
         * @private
         * @param password {string}
         * @param salt {string}
         * @param options {object}
         * @returns {arrayBuffer}
         */
        generateKey: (password, salt, options = {}) => {
          if (options.interruptStep) {
            throw new Error(
              "interruptStep option is not being supported and will be overwritten to `0`. For requesting this feature please post an issue here: https://github.com/VivyTeam/krypt-web/issues"
            );
          }

          let derivedKey = null;
          scrypt(
            password,
            salt,
            {
              N: 16384,
              r: 8,
              p: 1,
              dkLen: 32,
              ...options,
              interruptStep: 0
            },
            key => {
              derivedKey = key;
            }
          );
          return derivedKey;
        }
      };
    default:
      throw new Error(
        `The algorithm you requested is not currently supported. Supported are ${types.map(
          type => ` ${type}`
        )}.`
      );
  }
};
