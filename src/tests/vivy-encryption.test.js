import { encrypt, decrypt } from "../../src/lib/vivy-encryption";
import { generateKey } from "../../src/lib/rsa-oaep";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";

describe("vivy-encryption", () => {
  const expect = window.expect;

  it("should encrypt data and decrypt it back.", async () => {
    const { privateKey, publicKey } = await generateKey();
    const originalString = "Encrypted secret message";
    const buffer = stringToArrayBuffer(originalString);

    const { cipherSecrets, cipherData } = await encrypt(publicKey, buffer);
    const arrayBufferData = await decrypt(
      privateKey,
      cipherSecrets,
      cipherData
    );

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });
});
