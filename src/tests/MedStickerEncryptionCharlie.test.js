import {
  encrypt,
  decrypt,
  hash,
  splitKeys,
  fingerprint
} from "../lib/MedStickerEncryptionCharlie";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";
import create from "../lib/factory";
import { CHARLIE_STATIC_SALT } from "../lib/constants";

const gcm = create("AES-GCM");

describe("MedStickerEncryption, version charlie", () => {
  const originalString = "Encrypted secret message";
  const buffer = stringToArrayBuffer(originalString);
  const pin = "pinNormally24Characters!";
  const pinSecret = "pinSecret";
  const secret = pin + pinSecret;

  it("should encrypt data and decrypt it back", async () => {
    const iv = new ArrayBuffer(128);
    const pinFingerprint = await hash(secret, CHARLIE_STATIC_SALT);
    const { key } = splitKeys(pinFingerprint);
    const cryptoKey = await gcm.importKey(key);

    const encryptedArrayBuffer = await encrypt(cryptoKey, iv, buffer);
    const arrayBufferData = await decrypt(cryptoKey, iv, encryptedArrayBuffer);
    const result = arrayBufferToString(arrayBufferData);

    expect(result).toEqual(originalString);
  });

  it("should throw error on decrypt when the IV used is not the same as the one used for encryption", async () => {
    const iv = new ArrayBuffer(128);
    const pinFingerprint = await hash(secret, CHARLIE_STATIC_SALT);
    const { key } = splitKeys(pinFingerprint);
    const cryptoKey = await gcm.importKey(key);

    const encryptedArrayBuffer = await encrypt(cryptoKey, iv, buffer);
    const anotherIv = new ArrayBuffer(1);

    let error;
    try {
      await decrypt(cryptoKey, anotherIv, encryptedArrayBuffer);
    } catch (err) {
      error = err;
    } finally {
      expect(error.message).toEqual("DecryptionFailed");
    }
  });

  it("should return a string in the form of charlie:{fingerprint}", async () => {
    const hashed = await hash(secret, CHARLIE_STATIC_SALT);
    const fingerprintString = fingerprint(hashed);

    expect(fingerprintString).toContain(`charlie:`);
  });

  it("should split the keys of the hashed value and validate that the `fingerprintFile` that is being returned is in the form of charlie:{fingerprint}", async () => {
    const hashed = await hash(secret, CHARLIE_STATIC_SALT);
    const { fingerprintFile } = splitKeys(hashed);

    expect(fingerprintFile).toContain(`charlie:`);
  });
});
