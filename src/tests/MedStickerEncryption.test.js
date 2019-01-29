import { encrypt, decrypt } from "../lib/MedStickerEncryption";
import { arrayBufferToString, stringToArrayBuffer } from "../lib/utilities";

describe("MedStickerEncryption", () => {
  const expect = window.expect;

  it("should encrypt data and decrypt it back.", async () => {
    const originalString = "Encrypted secret message";
    const buffer = stringToArrayBuffer(originalString);

    const data = await encrypt("christos", "christos", buffer);
    const arrayBufferData = await decrypt("christos", "christos", data);

    const result = arrayBufferToString(arrayBufferData);
    expect(result).to.deep.equal(originalString);
  });
});
