import {
  adamEncrypt,
  encrypt,
  decrypt,
  deriveKey,
  accessSignature
} from "../lib/MedStickerEncryption";
import { ADAM, BRITNEY } from "../lib/constants";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";

const algorithm = {
  [ADAM]: { encrypt: adamEncrypt },
  [BRITNEY]: { encrypt }
};
describe("MedStickerEncryption", () => {
  const { expect } = window;

  Object.keys(algorithm).forEach(versionName => {
    it(`${versionName}: should encrypt data and decrypt it back`, async () => {
      const originalString = "Encrypted secret message from adam";
      const buffer = stringToArrayBuffer(originalString);
      const { key, iv, version } = deriveKey(
        "7i6XA2zz",
        "qmHuG263",
        versionName
      );

      const { data } = await algorithm[versionName].encrypt(
        "7i6XA2zz",
        "qmHuG263",
        buffer
      );
      const arrayBufferData = await decrypt({ key, iv, version }, data);

      const result = arrayBufferToString(arrayBufferData);
      expect(result).to.deep.equal(originalString);
    });

    it(`${versionName}: should throw error on decrypt with wrong iv`, async () => {
      const originalString = "Encrypted secret message from adam";
      const buffer = stringToArrayBuffer(originalString);
      const { key, version } = deriveKey("7i6XA2zz", "qmHuG263", ADAM);

      const { data } = await algorithm[versionName].encrypt(
        "7i6XA2zz",
        "qmHuG263",
        buffer
      );

      let error;
      try {
        await decrypt({ key, iv: new ArrayBuffer(0), version }, data);
      } catch (err) {
        error = err;
      } finally {
        expect(error.message).to.be.equal("DecryptionFailed");
      }
    });

    it(`${versionName}: should return a signature in the form of {versionName}-sha256:{base64EncodedSignature}`, async () => {
      const { key, iv } = deriveKey("7i6XA2zz", "qmHuG263", versionName);
      const salt = stringToArrayBuffer(
        "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
      );
      const signature = await accessSignature(
        { key, iv, version: versionName },
        salt
      );
      expect(signature).to.be.a("string");
    });
  });
});
