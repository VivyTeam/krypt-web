import create from "../../src/lib/factory";

import {
  arrayBufferToString,
  stringToArrayBuffer,
  generateInitialVector
} from "../lib/utilities";

describe("aes-gcm", () => {
  const expect = window.expect;
  let aes = null;
  let mockKey = null;
  let mockIv = null;

  before(async () => {
    aes = create("aes-gcm");
    const iv = await generateInitialVector();
    const key = await aes.generateKey();
    mockIv = iv;
    mockKey = key;
  });

  async function encryptStringIntoBase64(originalString) {
    const buffer = stringToArrayBuffer(originalString);
    const cipherText = await aes.encrypt(mockKey, mockIv, buffer);
    const string = arrayBufferToString(cipherText);
    return window.btoa(string);
  }

  async function decryptBase64IntoString(base64) {
    const decoded = window.atob(base64);
    const buffer = stringToArrayBuffer(decoded);
    const decrypted = await aes.decrypt(mockKey, mockIv, buffer);
    return arrayBufferToString(decrypted);
  }

  it("should encrypt a plain text, then decrypt the result. Result should be the same with original.", async () => {
    const originalString = "Encrypted secret message";
    const encryptedMessage = await encryptStringIntoBase64(originalString);
    const result = await decryptBase64IntoString(encryptedMessage);

    expect(result).to.equal(originalString);
  });

  it("should generate key. encrypt. export it. import key. decrypt.", async () => {
    const originalString = "Encrypted secret message";
    const encryptedMessage = await encryptStringIntoBase64(originalString);

    const rawKey = await aes.exportKey(mockKey);
    const importedKey = await aes.importKey(rawKey);

    const result = await decryptBase64IntoString(encryptedMessage, importedKey);

    expect(result).to.equal(originalString);
  });
});
