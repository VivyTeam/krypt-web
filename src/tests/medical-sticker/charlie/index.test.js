import {
  encrypt,
  decrypt,
  hash,
  splitKeys,
  fingerprint
} from "../../../lib/medical-sticker/charlie";
import {
  arrayBufferToString,
  stringToArrayBuffer
} from "../../../lib/utilities";
import { CHARLIE_STATIC_SALT } from "../../../lib/constants";

describe("Medical-id, version charlie", () => {
  const originalString = "Encrypted secret message";
  const buffer = stringToArrayBuffer(originalString);
  const pin = "pinNormally24Characters!";
  const pinSecret = "pinSecret";
  const secret = pin + pinSecret;

  it("should encrypt data and decrypt it back", async () => {
    const iv = new ArrayBuffer(128);
    const pinFingerprint = hash(secret, CHARLIE_STATIC_SALT);
    const { key } = splitKeys(pinFingerprint);

    const encryptedArrayBuffer = await encrypt(key, iv, buffer);
    const arrayBufferData = await decrypt(key, iv, encryptedArrayBuffer);
    const result = arrayBufferToString(arrayBufferData);

    expect(result).toEqual(originalString);
  });

  it("should throw error on decrypt when the IV used is not the same as the one used for encryption", async () => {
    const iv = new ArrayBuffer(128);
    const pinFingerprint = hash(secret, CHARLIE_STATIC_SALT);
    const { key } = splitKeys(pinFingerprint);

    const encryptedArrayBuffer = await encrypt(key, iv, buffer);
    const anotherIv = new ArrayBuffer(1);

    let error;
    try {
      await decrypt(key, anotherIv, encryptedArrayBuffer);
    } catch (err) {
      error = err;
    } finally {
      expect(error.message).toEqual("DecryptionFailed");
    }
  });

  it("should return a string in the form of charlie:{fingerprint}", () => {
    const hashed = hash(secret, CHARLIE_STATIC_SALT);
    const fingerprintString = fingerprint(hashed);

    expect(fingerprintString).toContain(`charlie:`);
  });

  it("should split the keys of the hashed value and validate that the `fingerprintFile` that is being returned is in the form of charlie:{fingerprint}", () => {
    const hashed = hash(secret, CHARLIE_STATIC_SALT);
    const { fingerprintFile } = splitKeys(hashed);

    expect(fingerprintFile).toContain(`charlie:`);
  });
});
