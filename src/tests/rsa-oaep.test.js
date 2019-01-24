import { generateKey, encrypt, decrypt } from "../../src/lib/rsa-oaep";
import {
  arrayBufferToString,
  stringToArrayBuffer
} from "../lib/utilities";

describe("rsa-oaep", () => {
  const expect = window.expect;
  let mockPrivateKey = null;
  let mockPublicKey = null;

  before(async () => {
    const { privateKey, publicKey } = await generateKey();
    mockPrivateKey = privateKey;
    mockPublicKey = publicKey;
  });

  async function encryptStringIntoBase64(originalString) {
    const buffer = stringToArrayBuffer(originalString);
    const cipherText = await encrypt(mockPublicKey, buffer);
    const string = arrayBufferToString(cipherText);
    return window.btoa(string);
  }

  async function decryptBase64IntoString(base64) {
    const decoded = window.atob(base64);
    const buffer = stringToArrayBuffer(decoded);
    const decrypted = await decrypt(mockPrivateKey, buffer);
    return arrayBufferToString(decrypted);
  }

  it("should encrypt a plain text, then decrypt the result. Result should be the same with original.", async () => {
    const originalString = "Encrypted secret message";
    const encryptedMessage = await encryptStringIntoBase64(originalString);
    const result = await decryptBase64IntoString(encryptedMessage);

    expect(result).to.equal(originalString);
  });
});
