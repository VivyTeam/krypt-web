import create from "./factory";
import { arrayBufferToString, encode } from "./utilities";
import { CHARLIE } from "./constants";

const scrypt = create("scrypt");
const gcm = create("AES-GCM");

/**
 *
 * @param secret
 * @param salt
 * @returns {PromiseLike<CryptoKeyPair> | PromiseLike<CryptoKey> | PromiseLike<CryptoKeyPair | CryptoKey>}
 */
export async function hash(secret, salt) {
  try {
    return await scrypt.generateKey(secret, salt);
  } catch (e) {
    throw new Error("HashFailed");
  }
}

/**
 *
 * @param hashed
 * @returns {Promise<string>}
 */
export function fingerprintSecret(hashed) {
  const base64EncodedFingerprintSecret = encode(arrayBufferToString(hashed));
  return `${CHARLIE}-sha256:${base64EncodedFingerprintSecret}`;
}

/**
 *
 * @param array
 * @returns {{cryptoKey: ArrayBufferLike, accessKey: ArrayBufferLike}}
 */
export function splitKeys(array) {
  const arrayLength = array.length;
  const cryptoKey = array.slice(0, arrayLength / 2);
  const fingerprintFile = array.slice(arrayLength / 2, arrayLength);

  return {
    key: new Uint8Array(cryptoKey).buffer,
    fingerprintFile: new Uint8Array(fingerprintFile).buffer
  };
}

/**
 *
 * @returns {string}
 */
export function generateRandomAesIv() {
  const initializationVector = new Uint8Array(12);
  return window.crypto.getRandomValues(initializationVector);
}

/**
 *
 * @param toEncryptBytes
 * @param key
 * @param iv
 * @returns {PromiseLike<ArrayBuffer>}
 */
export async function encrypt(toEncryptBytes, key, iv) {
  try {
    return await gcm.encrypt(key, iv, toEncryptBytes);
  } catch (e) {
    throw new Error("EncryptionFailed");
  }
}

/**
 *
 * @param encryptedData
 * @param key
 * @param iv
 * @returns {PromiseLike<ArrayBuffer>}
 */
export async function decrypt(encryptedData, key, iv) {
  try {
    return await gcm.decrypt(key, iv, encryptedData);
  } catch (e) {
    throw new Error("DecryptionFailed");
  }
}
