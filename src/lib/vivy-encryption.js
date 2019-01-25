import {
  generateInitialVector,
  arrayBufferToString,
  stringToArrayBuffer
} from "./utilities";
import {
  generateKey as aesGenerateKey,
  importKey as aesImportKey,
  exportKey as aesExportKey,
  encrypt as aesEncrypt,
  decrypt as aesDecrypt
} from "./aes-gcm";
import { encrypt as rsaEncrypt, decrypt as rsaDecrypt } from "./rsa-oaep";

/*
  Vivy-Encryption - Encrypt
  Encrypts aesKey and iv using RSA-OAEP to create a so called 'envelope'.
  Encrypts data using AES-GCM.
  Returns an object with the encrypted secrets (key,iv) and the data.
*/
export async function encrypt(publicKey, buffer) {
  const iv = await generateInitialVector();
  const aesKey = await aesGenerateKey();
  const aesExportedKey = await aesExportKey(aesKey);
  const ivBase64 = transformIvToBase64(iv);
  const aesKeyBase64 = transformKeyToBase64(aesExportedKey);
  const jsonString = JSON.stringify({
    base64EncodedIV: ivBase64,
    base64EncodedKey: aesKeyBase64
  });
  const bufferSecrets = stringToArrayBuffer(jsonString);

  const cipherKeyIv = await rsaEncrypt(publicKey, bufferSecrets);
  const cipherData = await aesEncrypt(aesKey, iv, buffer);

  return { cipherKeyIv, cipherData };
}

/*
   Vivy-Encryption - Decrypt
*/
export async function decrypt(privateKey, cipherKeyIv, cipherData) {
  const { key, iv } = await decryptCipherKeyIv(privateKey, cipherKeyIv);
  return await decryptCipherData(key, iv, cipherData);
}

/*
   Vivy-Encryption - Decrypts cipher secrets (key, iv) via RSA-OAEP.
   Returned format is ArrayBuffer.
*/
async function decryptCipherKeyIv(privateKey, cipherKeyIv) {
  const secretsArrayBuffer = await rsaDecrypt(privateKey, cipherKeyIv);
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
  const key = await aesImportKey(arrayBufferKey);
  const iv = new Uint8Array(arrayBufferIv);

  return await aesDecrypt(key, iv, cipherData);
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
