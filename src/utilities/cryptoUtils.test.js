import { generateKey, encryptMessage, decryptMessage } from "./cryptoUtils";

describe("crypto utilities", () => {
  const expect = window.expect;
  let mockPrivateKey = null;
  let mockPublicKey = null;

  before(async () => {
    const { privateKey, publicKey } = await generateKey();
    mockPrivateKey = privateKey;
    mockPublicKey = publicKey;
  });

  it("should encrypt a plain text, then decrypt the result. Result should be the same with original.", async () => {
    const originalString = "Encrypted secret message";

    const encrypted = await encryptMessage(mockPublicKey, originalString);
    const result = await decryptMessage(mockPrivateKey, encrypted);

    expect(result).to.equal(originalString);
  });
});
