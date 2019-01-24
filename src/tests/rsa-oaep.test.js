import {
  generateKey,
  encrypt,
  decrypt,
  exportKey,
  importKey
} from "../../src/lib/rsa-oaep";
import {
  arrayBufferToString,
  stringToArrayBuffer,
  toArrayBuffer,
  toPem
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

  async function encryptStringIntoBase64(originalString, key = mockPublicKey) {
    const buffer = stringToArrayBuffer(originalString);
    const cipherText = await encrypt(key, buffer);
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

  it("should generate key. encrypt. export it. transform it to pem. transform it back to buffer. import key. decrypt.", async () => {
    const originalString = "Encrypted secret message";
    const encryptedMessage = await encryptStringIntoBase64(originalString);

    const exportedKey = await exportKey(mockPublicKey);
    const pem = toPem(exportedKey);

    const arrayBuffer = toArrayBuffer(pem);
    const importedKey = await importKey(arrayBuffer);

    const result = await decryptBase64IntoString(encryptedMessage, importedKey);

    expect(result).to.equal(originalString);
  });
});
