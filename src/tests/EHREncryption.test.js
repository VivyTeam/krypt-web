import { encrypt, decrypt } from "../lib/EHREncryption";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";
import create from "../lib/factory";

describe("EHREncryption", () => {
  let rsa = null;

  beforeAll(async () => {
    rsa = create("RSA-OAEP");
  });

  it("should encrypt data and decrypt it back.", async () => {
    const { privateKey, publicKey } = await rsa.generateKey();
    const originalString = "Encrypted secret message";
    const buffer = stringToArrayBuffer(originalString);

    const { cipherKey, data } = await encrypt(publicKey, buffer);
    const arrayBufferData = await decrypt(privateKey, { cipherKey, data });

    const result = arrayBufferToString(arrayBufferData);
    expect(result).toEqual(originalString);
  });
});
