import { stringToArrayBuffer, arrayBufferToString } from "../lib/utilities";

describe("basic utilities", () => {
  it("should convert a String to ArrayBuffer and back. Result should be equal.", async () => {
    const originalString = "Mock secret message";
    const arrayBuffer = stringToArrayBuffer(originalString);
    const result = arrayBufferToString(arrayBuffer);

    expect(result).toBe(originalString);
  });

  it("should convert an ArrayBuffer to String and back. Result should be the equal", async () => {
    const originalArrayBuffer = new ArrayBuffer(100);
    const string = arrayBufferToString(originalArrayBuffer);
    const result = stringToArrayBuffer(string);

    expect(result).toEqual(originalArrayBuffer);
  });
});
