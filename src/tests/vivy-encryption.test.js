import { encrypt, decrypt } from "../../src/lib/vivy-encryption";
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

    const { cipherKeyIv, cipherData } = await encrypt(publicKey, buffer);
    const arrayBufferData = await decrypt(privateKey, cipherKeyIv, cipherData);

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });
});
