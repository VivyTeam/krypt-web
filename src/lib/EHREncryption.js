import {
  generateInitialVector,
  arrayBufferToString,
  stringToArrayBuffer
} from "./utilities";
import create from "./factory";

const aes = create("AES-GCM");
const rsa = create("RSA-OAEP");

/**
 * Encrypts aesKey and iv using RSA-OAEP to create a so called 'envelope'. Encrypts data using AES-GCM.
 * @param publicKey {arrayBuffer}
 * @param buffer {arrayBuffer}
 * @returns {Promise<{cipher: ArrayBuffer, cipherData: ArrayBuffer}>}
 */
export async function encrypt(publicKey, buffer) {
  const iv = await generateInitialVector();
  const key = await aes.generateKey();

  const cipher = await encryptKeyIv(publicKey, key, iv);
  const cipherData = await aes.encrypt(key, iv, buffer);

  return { cipher, cipherData };
}

/**
 * Decrypts data
 * @param privateKey {arrayBuffer}
 * @param cipher {arrayBuffer}
 * @param cipherData {arrayBuffer}
 * @returns {Promise<*>}
 */
export async function decrypt(privateKey, { cipher, cipherData }) {
  const { key, iv } = await decryptKeyIv(privateKey, cipher);
  const importedKey = await aes.importKey(key);
  const uint8Iv = new Uint8Array(iv);

  return await aes.decrypt(importedKey, uint8Iv, cipherData);
}

/**
 * Encrypts cipher (key, iv) via RSA-OAEP.
 * @param publicKey {arrayBuffer}
 * @param key {arrayBuffer}
 * @param iv {arrayBuffer}
 * @returns {Promise<*|PromiseLike<ArrayBuffer>>}
 */
async function encryptKeyIv(publicKey, key, iv) {
  const aesExportedKey = await aes.exportKey(key);
  const base64EncodedIV = transformIvToBase64(iv);
  const base64EncodedKey = transformKeyToBase64(aesExportedKey);
  const jsonStringSecrets = JSON.stringify({
    base64EncodedIV,
    base64EncodedKey
  });

  return rsa.encrypt(publicKey, jsonStringSecrets);
}

/**
 * Decrypts cipher (key, iv) via RSA-OAEP.
 * @param privateKey {arrayBuffer}
 * @param cipher {arrayBuffer}
 * @returns {Promise<{key: *, iv: *}>}
 */
async function decryptKeyIv(privateKey, cipher) {
  const secretsArrayBuffer = await rsa.decrypt(privateKey, cipher);
  const secretsJsonString = arrayBufferToString(secretsArrayBuffer);
  const { base64EncodedKey, base64EncodedIV } = JSON.parse(secretsJsonString);
  const key = stringToArrayBuffer(window.atob(base64EncodedKey));
  const iv = stringToArrayBuffer(window.atob(base64EncodedIV));
  return { key, iv };
}

/**
 * Transforms key array buffer to base 64 string.
 * @param key {arrayBuffer}
 * @returns {string}
 */
function transformKeyToBase64(key) {
  const string = arrayBufferToString(key);
  return window.btoa(string);
}

/**
 * Transforms iv array buffer to base 64 string.
 * @param iv {arrayBuffer}
 * @returns {string}
 */
function transformIvToBase64(iv) {
  const buffer = iv.buffer;
  const string = arrayBufferToString(buffer);
  return window.btoa(string);
}
