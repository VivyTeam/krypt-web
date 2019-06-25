import create from "./factory";
import { arrayBufferToHex } from "./utilities";
import { CHARLIE } from "./constants";

const scrypt = create("scrypt");
const gcm = create("AES-GCM");

/**
 * @param secret {string}
 * @param salt {string}
 * @returns {Array}
 */
export function hash(secret, salt) {
  try {
    return scrypt.generateKey(secret, salt);
  } catch (e) {
    throw new Error("HashFailed");
  }
}

/**
 * Given a hashed string, returns a concatenated string
 * that contains the version of the encryption its being
 * used and the incoming string in hex format
 * @param hashed {string}
 * @returns {string}
 */

export function fingerprint(hashed) {
  const hexFingerprintSecret = arrayBufferToHex(hashed);
  return `${CHARLIE}:${hexFingerprintSecret}`;
}

/**
 * Takes an array, splits it in half,
 * from the first bit creates an ArrayBuffer
 * from the second bit creates a string that
 * contains a secret but also indicates the version of the algorithm used
 * @param array {Array}
 * @returns {{fingerprintFile: string, key: ArrayBufferLike}}
 */
export function splitKeys(array) {
  const arrayLength = array.length;
  const key = array.slice(0, arrayLength / 2);
  const fingerprintFile = array.slice(arrayLength / 2, arrayLength);
  const fingerprintArrayBuffer = new Uint8Array(fingerprintFile).buffer;
  const hexFingerprintSecret = fingerprint(fingerprintArrayBuffer);
  return {
    key: new Uint8Array(key).buffer,
    fingerprintFile: hexFingerprintSecret
  };
}

/**
 * @param key {CryptoKey}
 * @param iv {Uint8Array}
 * @param toEncryptBytes {ArrayBuffer}
 * @returns {Promise<ArrayBuffer>}
 */
export async function encrypt(key, iv, toEncryptBytes) {
  try {
    return await gcm.encrypt(key, iv, toEncryptBytes);
  } catch (e) {
    throw new Error("EncryptionFailed");
  }
}

/**
 * @param key {CryptoKey}
 * @param iv {ArrayBuffer}
 * @param encryptedBytes {ArrayBuffer}
 * @returns {Promise<ArrayBuffer>}
 */
export async function decrypt(key, iv, encryptedBytes) {
  try {
    return await gcm.decrypt(key, iv, encryptedBytes);
  } catch (e) {
    throw new Error("DecryptionFailed");
  }
}
