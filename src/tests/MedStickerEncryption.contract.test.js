import {
  accessSignature,
  adamEncrypt,
  encrypt,
  decrypt,
  deriveKey
} from "../lib/MedStickerEncryption";
import {
  arrayBufferToString,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  stringToArrayBuffer
} from "../lib/utilities";
import { ADAM, BRITNEY } from "../lib/constants";

const algorithms = [
  {
    name: ADAM,
    encrypt: adamEncrypt,
    code: "7i6XA2zz",
    pin: "qmHuG263",
    givenKeyBase64: "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=",
    givenIvBase64: "gi44bZGuBBdLpMISpeppWQ==",
    givenEncryptedDataBase64:
      "rIfjcSAsEh/so+5+ijho97FmIRH36LCCkD/a0V0HWsmw01SEpxoYrQjp5Il5IITw"
  },
  {
    name: BRITNEY,
    encrypt,
    code: "7i6XA2zz",
    pin: "qmHuG263",
    givenKeyBase64: "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=",
    givenIvBase64: "aoiywBzTwYxzKQz45UxWaQ==",
    givenEncryptedDataBase64:
      "1EkGWJAKP0BG2CAstCFcq8ysbOEvYwruJrrJUBRVGQMe8590wfdKge/jfKcLwEjFg7Q="
  }
];

describe("MedStickerEncryption contract", () => {
  algorithms.forEach(algorithm => {
    describe(`version ${algorithm.name}`, () => {
      it("deriveKey value should match the value on the contract", async () => {
        const { key, iv } = deriveKey(
          algorithm.code,
          algorithm.pin,
          algorithm.name
        );

        const keyBase64 = arrayBufferToBase64(key);
        const ivBase64 = arrayBufferToBase64(iv);

        expect(keyBase64).to.deep.equal(algorithm.givenKeyBase64);
        expect(ivBase64).to.deep.equal(algorithm.givenIvBase64);
      });

      it("encrypted data should match the values on the contract", async () => {
        const message = "A Healthier Life is a Happier Life";
        const messageBuffer = stringToArrayBuffer(message);
        const { data } = await algorithm.encrypt(
          algorithm.code,
          algorithm.pin,
          messageBuffer
        );
        const dataBase64 = arrayBufferToBase64(data);

        expect(dataBase64).to.deep.equal(algorithm.givenEncryptedDataBase64);
      });

      it("decrypted data should match the values on the contract", async () => {
        const key = base64ToArrayBuffer(algorithm.givenKeyBase64);
        const iv = base64ToArrayBuffer(algorithm.givenIvBase64);
        const encryptedBuffer = base64ToArrayBuffer(
          algorithm.givenEncryptedDataBase64
        );

        const data = await decrypt(
          { key, iv, version: algorithm.name },
          encryptedBuffer
        );
        const plainText = arrayBufferToString(data);

        expect(plainText).to.deep.equal("A Healthier Life is a Happier Life");
      });
    });
  });

  it("Signature should be equal as the contracts", async () => {
    const code = "7i6XA2zz";
    const pin = "qmHuG263";
    const { key, iv } = deriveKey(code, pin, BRITNEY);
    const signature = await accessSignature(
      { key, iv, version: BRITNEY },
      "98C1EB4EE93476743763878FCB96A25FBC9A175074D64004779ECB5242F645E6"
    );
    expect(signature).to.deep.equal(
      "britney-sha256:RonmY2BVOex5wlGRrLPkXn/MZV1Rhot4wRc9+cuK0zY="
    );
  });
});
