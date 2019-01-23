
import {
  stringToArrayBuffer,
  arrayBufferToString,
  keyBufferToPEM
} from "./basicUtils";

import { generateKey } from "./cryptoUtils";

describe("basic utilities", () => {
  var expect = window.expect;

  it("should convert a string to array buffer", async () => {
    const arrayBuffer = stringToArrayBuffer("Mock secret message");
    expect(arrayBuffer.byteLength).to.be(5);
  });

  it("should convert an array buffer to string", async () => {
    var buffer = new ArrayBuffer(100);
    const binary = arrayBufferToString(buffer);
    expect(binary.length).to.be(100);
  });

  it("should convert a key buffer to PEM format", async () => {
    const { key, publicKey } = await generateKey();
    const pemEncodedKey = keyBufferToPEM(publicKey)
    console.log(pemEncodedKey)
  });
});
