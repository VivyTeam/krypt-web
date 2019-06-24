import {
  encrypt,
  decrypt,
  hash,
  splitKeys,
  generateRandomAesIv,
  fingerprintSecret
} from "../lib/MedStickerEncryptionV2";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";
import create from "../lib/factory";

const gcm = create("AES-GCM");

describe("second version of MedStickerEncryption", () => {
  const originalString = "Encrypted secret message";
  const buffer = stringToArrayBuffer(originalString);
  const pin = "pinNormally24Characters!";
  const pinSecret = "pinSecret";
  const secret = pin + pinSecret;
  const salt = "5f1288159017d636c13c1c1b2835b8a871780bc2";

  it("should encrypt data and decrypt it back", async () => {
    const iv = generateRandomAesIv();
    const pinFingerprint = await hash(secret, salt);
    const { key } = splitKeys(pinFingerprint);
    const cryptoKey = await gcm.importKey(key);

    const encryptedArrayBuffer = await encrypt(buffer, cryptoKey, iv);
    const arrayBufferData = await decrypt(encryptedArrayBuffer, cryptoKey, iv);
    const result = arrayBufferToString(arrayBufferData);

    expect(result).toEqual(originalString);
  });

  it("should throw error on decrypt when iv is different that on used for encryption", async () => {
    const iv = generateRandomAesIv();
    const pinFingerprint = await hash(secret, salt);
    const { key } = splitKeys(pinFingerprint);
    const cryptoKey = await gcm.importKey(key);

    const encryptedArrayBuffer = await encrypt(buffer, cryptoKey, iv);
    const anotherIv = generateRandomAesIv();

    let error;
    try {
      await decrypt(encryptedArrayBuffer, cryptoKey, anotherIv);
    } catch (err) {
      error = err;
    } finally {
      expect(error.message).toEqual("DecryptionFailed");
    }
  });

  it("should return a fingerprint in the form of {name}-sha256:{base64Fingerprint}", async () => {
    const fingerprint = await hash(secret, salt);
    const fingerprintSecretString = fingerprintSecret(fingerprint);

    expect(fingerprintSecretString).toContain(`charlie-sha256:`);
  });
});
