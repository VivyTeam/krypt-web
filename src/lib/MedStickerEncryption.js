import create from "./factory";
import { ADAM, BRITNEY } from "./constants";
import { arrayBufferToString, stringToArrayBuffer } from "./utilities";

const scrypt = create("scrypt");
const cbc = create("AES-CBC");
const gcm = create("AES-GCM");

/**
 * @param code {string}
 * @param pin {string}
 * @param toEncryptBytes {arrayBuffer}
 * @returns {Promise<ArrayBuffer>}
 */
export async function adamEncrypt(code, pin, toEncryptBytes) {
  const arrayBufferKey = scrypt.generateKey(code, pin);
  const arrayBufferIv = scrypt.generateKey(code, pin, { dkLen: 16 });

  const key = await cbc.importKey(arrayBufferKey);

  try {
    const data = await cbc.encrypt(key, arrayBufferIv, toEncryptBytes);
    return {
      data,
      MedStickerCipherAttr: {
        key: arrayBufferKey,
        iv: arrayBufferIv,
        version: ADAM
      }
    };
  } catch {
    throw new Error("EncryptionFailed");
  }
}

/**
 * @param code {string}
 * @param pin {string}
 * @param toEncryptBytes {arrayBuffer}
 * @returns {Promise<ArrayBuffer>}
 */
export async function encrypt(code, pin, toEncryptBytes) {
  const arrayBufferKey = scrypt.generateKey(code, pin, { r: 10 });
  const arrayBufferIv = scrypt.generateKey(code, pin, { dkLen: 16 });

  const key = await gcm.importKey(arrayBufferKey);

  try {
    const data = await gcm.encrypt(key, arrayBufferIv, toEncryptBytes);
    return {
      data,
      MedStickerCipherAttr: {
        key: arrayBufferKey,
        iv: arrayBufferIv,
        version: BRITNEY
      }
    };
  } catch {
    throw new Error("EncryptionFailed");
  }
}

/**
 * @param key {arrayBuffer}
 * @param iv {arrayBuffer}
 * @param encryptedData {arrayBuffer}
 * @param version {string}
 * @returns {Promise<ArrayBuffer>}
 */
export async function decrypt({ key, iv, version }, encryptedData) {
  let encryption;
  switch (version) {
    case ADAM:
      encryption = cbc;
      break;
    case BRITNEY:
      encryption = gcm;
      break;
    default:
      throw new Error(
        "Wrong version is being used. Use either 'adam' or 'britney'."
      );
  }
  const cryptoKey = await encryption.importKey(key);

  try {
    return await encryption.decrypt(cryptoKey, iv, encryptedData);
  } catch {
    throw new Error("DecryptionFailed");
  }
}

/**
 * @param code {string}
 * @param pin {string}
 * @param version {string}
 * @returns {{key: *, iv: *, version: *}}
 */
export function deriveKey(code, pin, version) {
  let key, iv;
  switch (version) {
    case ADAM:
      key = scrypt.generateKey(code, pin);
      iv = scrypt.generateKey(code, pin, { dkLen: 16 });
      break;
    case BRITNEY:
      key = scrypt.generateKey(code, pin, { r: 10 });
      iv = scrypt.generateKey(code, pin, { dkLen: 16 });
      break;
    default:
      throw new Error(
        "Wrong version is being used. Use either 'adam' or 'britney'."
      );
  }

  return { key, iv, version };
}

/**
 * @param key
 * @param iv
 * @param version
 * @param salt
 * @returns {Promise<void>}
 */
export async function accessSignature({ key, iv, version }, salt) {
  const utf8Key = new Uint8Array(key);
  const utf8Iv = new Uint8Array(iv);
  const utf8Salt = new Uint8Array(stringToArrayBuffer(salt));
  const signatureBytes = new Uint8Array([...utf8Key, ...utf8Iv, ...utf8Salt]);
  const signatureArrayBuffer = await window.crypto.subtle.digest(
    "SHA-256",
    signatureBytes
  );
  const signatureString = arrayBufferToString(signatureArrayBuffer);
  const base64EncodedSignature = btoa(signatureString);
  return `sha256${base64EncodedSignature}`;
}
