import {
  arrayBufferToString,
  stringToArrayBuffer
} from "./utilities/convertions";

/*
  Generate an encryption key pair.
*/
export async function generateKey(bits = 4096) {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" }
    },
    true,
    ["encrypt", "decrypt"]
  );
}

/*
  Encrypts text.
*/
export async function encryptMessage(publicKey, text) {
  const buffer = stringToArrayBuffer(text);
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP"
    },
    publicKey,
    buffer
  );
  const string = arrayBufferToString(ciphertext);

  return window.btoa(string);
}

/*
  Decrypts ciphertext.
*/
export async function decryptMessage(privateKey, ciphertext) {
  const decoded = window.atob(ciphertext);
  const buffer = stringToArrayBuffer(decoded);
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    buffer
  );

  return arrayBufferToString(decrypted);
}
