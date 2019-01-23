import { arrayBufferToString, stringToArrayBuffer } from "./basicUtils";

/*
  Generate an encryption key pair.
*/
export async function generateKey(bits = 4096) {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" }
    },
    true,
    ["encrypt", "decrypt"]
  );

  return keyPair;
}

/*
  Decrypts text.
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
  const encrypted = window.btoa(string);

  return encrypted;
}

/*
  Decrypts ciphertext.
*/
export async function decryptMessage(privateKey, ciphertext) {
  const decoded = window.atob(ciphertext);
  const buffer = stringToArrayBuffer(decoded);

  let decrypted = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    buffer
  );

  return arrayBufferToString(decrypted);
}
