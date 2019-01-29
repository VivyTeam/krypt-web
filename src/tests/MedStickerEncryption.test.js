import { encrypt, decrypt } from "../lib/MedStickerEncryption";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";

describe("MedStickerEncryption", () => {
  const expect = window.expect;

  it("should encrypt data and decrypt it back.", async () => {
    const originalString = "Encrypted secret message";
    const buffer = stringToArrayBuffer(originalString);

    const data = await encrypt("foobar", "barfoo", buffer);
    const arrayBufferData = await decrypt("foobar", "barfoo", data);

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });
});
