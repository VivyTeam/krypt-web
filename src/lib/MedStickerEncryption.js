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
  const { key, iv } = deriveKey(code, pin, ADAM);

  const cryptoKey = await cbc.importKey(key);

  try {
    const data = await cbc.encrypt(cryptoKey, iv, toEncryptBytes);
    return {
      data,
      MedStickerCipherAttr: {
        key,
        iv,
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
  const { key, iv } = deriveKey(code, pin, BRITNEY);

  const cryptoKey = await gcm.importKey(key);

  try {
    const data = await gcm.encrypt(cryptoKey, iv, toEncryptBytes);
    return {
      data,
      MedStickerCipherAttr: {
        key,
        iv,
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
 * @returns {{key: *, iv: *, version: string}}
 */
export function deriveKey(code, pin, version) {
  let key, iv;
  switch (version) {
    case ADAM:
      key = scrypt.generateKey(pin, code);
      iv = scrypt.generateKey(key, pin, { dkLen: 16 });
      break;
    case BRITNEY:
      key = scrypt.generateKey(pin, code, { r: 10 });
      iv = scrypt.generateKey(key, pin, { r: 10, dkLen: 16 });
      break;
    default:
      throw new Error(
        "Wrong version is being used. Use either 'adam' or 'britney'."
      );
  }
  const utf8Key = new Uint8Array(key);
  const utf8Iv = new Uint8Array(iv);
  const keyBuffer = utf8Key.buffer;
  const ivBuffer = utf8Iv.buffer;

  return { key: keyBuffer, iv: ivBuffer, version };
}

/**
 * @param key {ArrayBuffer}
 * @param iv {ArrayBuffer}
 * @param version {string}
 * @param salt {string}
 * @returns {Promise<string>}
 */
export async function accessSignature({ key, iv, version }, salt) {
  if (!version) {
    throw new Error(
      "Wrong version is being used. Use either 'adam' or 'britney'."
    );
  }
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

  return `${version}-sha256:${base64EncodedSignature}`;
}
