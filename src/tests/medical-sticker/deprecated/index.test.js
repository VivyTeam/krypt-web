import {
  adamEncrypt,
  encrypt,
  decrypt,
  deriveKey,
  accessSignature
} from "../../../lib/medical-sticker/deprecated";
import { ADAM, BRITNEY } from "../../../lib/constants";
import {
  arrayBufferToString,
  stringToArrayBuffer
} from "../../../lib/utilities";

const algorithms = [
  { name: ADAM, encrypt: adamEncrypt },
  { name: BRITNEY, encrypt }
];

describe("Medical-id Encryption", () => {
  algorithms.forEach(algorithm => {
    describe(`version ${algorithm.name}`, () => {
      it("should encrypt data and decrypt it back", async () => {
        const originalString = "Encrypted secret message";
        const buffer = stringToArrayBuffer(originalString);
        const { key, iv, version } = deriveKey(
          "7i6XA2zz",
          "qmHuG263",
          algorithm.name
        );

        const { data } = await algorithm.encrypt(
          "7i6XA2zz",
          "qmHuG263",
          buffer
        );
        const arrayBufferData = await decrypt({ key, iv, version }, data);

        const result = arrayBufferToString(arrayBufferData);
        expect(result).toEqual(originalString);
      });

      it("should throw error on decrypt when the IV used is not the same as the one used for encryption", async () => {
        const originalString = "Encrypted secret message";
        const buffer = stringToArrayBuffer(originalString);
        const { key, version } = deriveKey("7i6XA2zz", "qmHuG263", ADAM);

        const { data } = await algorithm.encrypt(
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
          expect(error.message).toBe("DecryptionFailed");
        }
      });

      it("should return a signature in the form of {name}-sha256:{base64EncodedSignature}", async () => {
        const { key, iv } = deriveKey("7i6XA2zz", "qmHuG263", algorithm.name);
        const salt = stringToArrayBuffer(
          "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
        );
        const signature = await accessSignature(
          { key, iv, version: algorithm.name },
          salt
        );
        expect(signature).toContain(`${algorithm.name}-sha256:`);
      });
    });
  });
});
