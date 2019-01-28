import { encrypt, decrypt } from "../lib/EHREncryption";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";
import create from "../lib/factory";

describe("vivy-encryption", () => {
  const expect = window.expect;
  let rsa = null;

  before(async () => {
    rsa = create("RSA-OAEP");
  });

  it("should encrypt data and decrypt it back.", async () => {
    const { privateKey, publicKey } = await rsa.generateKey();
    const originalString = "Encrypted secret message";
    const buffer = stringToArrayBuffer(originalString);

    const { cipher, cipherData } = await encrypt(publicKey, buffer);
    const arrayBufferData = await decrypt(privateKey, { cipher, cipherData });

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });
});
