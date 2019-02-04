import {
  adamEncrypt,
  encrypt,
  decrypt,
  deriveKey,
  accessSignature
} from "../lib/MedStickerEncryption";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";

describe("MedStickerEncryption", () => {
  const expect = window.expect;
  it("ADAM: should encrypt data and decrypt it back", async () => {
    const originalString = "Encrypted secret message from adam";
    const buffer = stringToArrayBuffer(originalString);
    const { key, iv } = deriveKey("foobar", "barfoo", "adam");

    const {
      data,
      MedStickerCipherAttr: { version }
    } = await adamEncrypt("foobar", "barfoo", buffer);
    const arrayBufferData = await decrypt({ key, iv, version }, data);

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });

  it("BRITNEY: should encrypt data and decrypt it back", async () => {
    const originalString = "Encrypted secret message from britney";
    const buffer = stringToArrayBuffer(originalString);
    const { key, iv } = deriveKey("foobar", "barfoo");

    const {
      data,
      MedStickerCipherAttr: { version }
    } = await encrypt("foobar", "barfoo", buffer);
    const arrayBufferData = await decrypt({ key, iv, version }, data);

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });

  it("should return a signature in the form of sha256+${base64EncodedSignature}", async () => {
    const { key, iv } = deriveKey("foobar", "barfoo");
    const salt = stringToArrayBuffer("811247BC075144859010335F20D28C5E");

    const signature = await accessSignature({ key, iv }, salt);
    expect(signature).to.be.a("string");
  });
});
