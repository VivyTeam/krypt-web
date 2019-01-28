import {
  generateInitialVector,
  arrayBufferToString,
  stringToArrayBuffer
} from "./utilities";
import create from "./factory";

const aes = create("AES-GCM");
const rsa = create("RSA-OAEP");
/*
  Vivy-Encryption - Encrypt
  Encrypts aesKey and iv using RSA-OAEP to create a so called 'envelope'.
  Encrypts data using AES-GCM.
  Returns an object with the encrypted secrets (key,iv) and the data.
*/
export async function encrypt(publicKey, buffer) {
  const iv = await generateInitialVector();
  const aesKey = await aes.generateKey();
  const aesExportedKey = await aes.exportKey(aesKey);
  const base64EncodedIV = transformIvToBase64(iv);
  const base64EncodedKey = transformKeyToBase64(aesExportedKey);
  const jsonStringSecrets = JSON.stringify({
    base64EncodedIV,
    base64EncodedKey
  });

  const cipher = await rsa.encrypt(publicKey, jsonStringSecrets);
  const cipherData = await aes.encrypt(aesKey, iv, buffer);

  return { cipher, cipherData };
}

/*
   Vivy-Encryption - Decrypt
*/
export async function decrypt(privateKey, { cipher, cipherData }) {
  const { key, iv } = await decryptCipherKeyIv(privateKey, cipher);
  return await decryptCipherData(key, iv, cipherData);
}

/*
   Vivy-Encryption - Decrypts cipher secrets (key, iv) via RSA-OAEP.
   Returned format is ArrayBuffer.
*/
async function decryptCipherKeyIv(privateKey, cipher) {
  const secretsArrayBuffer = await rsa.decrypt(privateKey, cipher);
  const secretsJsonString = arrayBufferToString(secretsArrayBuffer);
  const { base64EncodedKey, base64EncodedIV } = JSON.parse(secretsJsonString);
  const key = stringToArrayBuffer(window.atob(base64EncodedKey));
  const iv = stringToArrayBuffer(window.atob(base64EncodedIV));
  return { key, iv };
}

/*
   Vivy-Encryption - Decrypts cipher data via AES-GCM.
   Returned format is ArrayBuffer.
*/
async function decryptCipherData(arrayBufferKey, arrayBufferIv, cipherData) {
  const key = await aes.importKey(arrayBufferKey);
  const iv = new Uint8Array(arrayBufferIv);

  return await aes.decrypt(key, iv, cipherData);
}

function transformKeyToBase64(key) {
  const string = arrayBufferToString(key);
  return window.btoa(string);
}

function transformIvToBase64(iv) {
  const buffer = iv.buffer;
  const string = arrayBufferToString(buffer);
  return window.btoa(string);
}
