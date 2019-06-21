import create from "./factory";

const scrypt = create("scrypt");
const gcm = create("AES-GCM");

/**
 *
 * @param secret
 * @param salt
 * @param options
 * @returns {PromiseLike<CryptoKeyPair> | PromiseLike<CryptoKey> | PromiseLike<CryptoKeyPair | CryptoKey>}
 */
export async function hash(secret, salt, options) {
  try {
    return await scrypt.generateKey(secret, salt, options);
  } catch (e) {
    throw new Error("HashFailed");
  }
}

/**
 *
 * @param array
 * @returns {{cryptoKey: ArrayBufferLike, accessKey: ArrayBufferLike}}
 */
export function splitKeys(array) {
  const arrayLength = array.length;
  const cryptoKey = array.slice(0, arrayLength / 2);
  const accessKey = array.slice(arrayLength / 2, arrayLength);

  return {
    cryptoKey: new Uint8Array(cryptoKey).buffer,
    accessKey: new Uint8Array(accessKey).buffer
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
