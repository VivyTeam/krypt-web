import {
  generateKey,
  encrypt,
  decrypt,
  exportKey,
  importKey
} from "../../src/lib/aes-gcm";
import {
  arrayBufferToString,
  stringToArrayBuffer,
  generateInitialVector
} from "../lib/utilities";

describe("aes-gcm", () => {
  const expect = window.expect;
  let mockKey = null;
  let mockIv = null;

  before(async () => {
    const iv = await generateInitialVector();
    const key = await generateKey();

    mockIv = iv;
    mockKey = key;
  });

  async function encryptStringIntoBase64(originalString) {
    const buffer = stringToArrayBuffer(originalString);
    const cipherText = await encrypt(mockKey, mockIv, buffer);
    const string = arrayBufferToString(cipherText);
    return window.btoa(string);
  }

  async function decryptBase64IntoString(base64) {
    const decoded = window.atob(base64);
    const buffer = stringToArrayBuffer(decoded);
    const decrypted = await decrypt(mockKey, mockIv, buffer);
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

    const rawKey = await exportKey(mockKey);
    const importedKey = await importKey(rawKey);

    const result = await decryptBase64IntoString(encryptedMessage, importedKey);

    expect(result).to.equal(originalString);
  });
});
