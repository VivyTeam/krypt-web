import { stringToArrayBuffer } from "./utilities";

export default type => {
  const types = ["aes-gcm", "rsa-oaep"];
  type = type.toLowerCase();

  switch (type) {
    case "aes-gcm":
      return {
        /**
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
         * @param arrayBufferKey {arrayBuffer}
         * @returns {PromiseLike<CryptoKey>}
         */
        importKey: arrayBufferKey =>
          window.crypto.subtle.importKey(
            "raw",
            arrayBufferKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          ),
        exportKey: key => window.crypto.subtle.exportKey("raw", key),
        /**
         * @param key {arrayBuffer}
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
         * @param key {arrayBuffer}
         * @param iv {arrayBuffer}
         * @param data {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        decrypt: (key, iv, data) =>
          window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv
            },
            key,
            data
          )
      };
    case "rsa-oaep":
      return {
        /**
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
         *
         * @param arrayBufferKey {arrayBuffer}
         * @returns {PromiseLike<CryptoKey>}
         */
        importKey: arrayBufferKey =>
          window.crypto.subtle.importKey(
            "spki",
            arrayBufferKey,
            { name: "RSA-OAEP", hash: { name: "SHA-256" } },
            false,
            ["encrypt"]
          ),
        /**
         * @param publicKey {arrayBuffer}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        exportKey: publicKey =>
          window.crypto.subtle.exportKey("spki", publicKey),
        /**
         * @param publicKey {arrayBuffer}
         * @param jsonString {string}
         * @returns {PromiseLike<ArrayBuffer>}
         */
        encrypt: (publicKey, jsonString) => {
          const arrayBuffer = stringToArrayBuffer(jsonString);
          return window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            arrayBuffer
          );
        },
        /**
         * @param privateKey {arrayBuffer}
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
    default:
      throw {
        type: "Not found",
        message: `The algorythm you requested is not currently supported. 
        Supported are ${types.map(type => ` ${type}`)}.`
      };
  }
};
