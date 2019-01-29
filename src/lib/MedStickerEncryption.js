import create from "./factory";

const scrypt = create("scrypt");
const cbc = create("AES-CBC");

/**
 *
 * @param code {string}
 * @param pin {string}
 * @param toEncryptBytes {arrayBuffer}
 * @returns {Promise<ArrayBuffer>}
 */
export async function encrypt(code, pin, toEncryptBytes) {
  const arrayBufferKey = scrypt.generateKey(code, pin);
  const arrayBufferIv = scrypt.generateKey(code, pin, { dkLen: 16 });

  const key = await cbc.importKey(arrayBufferKey);

  return await cbc.encrypt(key, arrayBufferIv, toEncryptBytes);
}

/**
 *
 * @param code {string}
 * @param pin {string}
 * @param encryptedData {arrayBuffer}
 * @returns {Promise<ArrayBuffer>}
 */
export async function decrypt(code, pin, encryptedData) {
  const arrayBufferKey = scrypt.generateKey(code, pin);
  const arrayBufferIv = scrypt.generateKey(code, pin, { dkLen: 16 });

  const key = await cbc.importKey(arrayBufferKey);

  return await cbc.decrypt(key, arrayBufferIv, encryptedData);
}
