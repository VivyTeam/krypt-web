import { stringToArrayBuffer, arrayBufferToString } from "./basicUtils";

describe("basic utilities", () => {
  const expect = window.expect;

  it("should convert a String to ArrayBuffer and back. Result should be equal.", async () => {
    const originalString = "Mock secret message";
    const arrayBuffer = stringToArrayBuffer(originalString);
    const result = arrayBufferToString(arrayBuffer);

    expect(result).to.equal(originalString);
  });

  it("should convert an ArrayBuffer to String and back. Result should be the equal", async () => {
    const originalArrayBuffer = new ArrayBuffer(100);
    const string = arrayBufferToString(originalArrayBuffer);
    const result = stringToArrayBuffer(string);

    expect(result).to.deep.equal(originalArrayBuffer);
  });
});
