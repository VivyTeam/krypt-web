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

it("ADAM: deriveKey value should match the value on the contract", async () => {
  const code = "7i6XA2zz";
  const pin = "qmHuG263";
  const { key, iv } = deriveKey(code, pin, ADAM);
  const givenKeyBase64 = "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=";
  const givenIvBase64 = "gi44bZGuBBdLpMISpeppWQ==";

  const keyBase64 = arrayBufferToBase64(key);
  const ivBase64 = arrayBufferToBase64(iv);

  expect(keyBase64).to.deep.equal(givenKeyBase64);
  expect(ivBase64).to.deep.equal(givenIvBase64);
});

it("ADAM: encrypted data should match the values on the contract", async () => {
  const message = "A Healthier Life is a Happier Life";
  const messageBuffer = stringToArrayBuffer(message);
  const code = "7i6XA2zz";
  const pin = "qmHuG263";
  const { data } = await adamEncrypt(code, pin, messageBuffer);
  const dataBase64 = arrayBufferToBase64(data);

  expect(dataBase64).to.deep.equal(
    "rIfjcSAsEh/so+5+ijho97FmIRH36LCCkD/a0V0HWsmw01SEpxoYrQjp5Il5IITw"
  );
});

it("ADAM: decrypted data should match the values on the contract", async () => {
  const resultKeyBase64 = "Pivil9wBlqECOP8qulkJnHFnIiIwSffQt4rXo27X4Uk=";
  const resultIvBase64 = "gi44bZGuBBdLpMISpeppWQ==";
  const encryptedDataBase64 =
    "rIfjcSAsEh/so+5+ijho97FmIRH36LCCkD/a0V0HWsmw01SEpxoYrQjp5Il5IITw";

  const key = base64ToArrayBuffer(resultKeyBase64);
  const iv = base64ToArrayBuffer(resultIvBase64);
  const encryptedBuffer = base64ToArrayBuffer(encryptedDataBase64);

  const data = await decrypt({ key, iv, version: ADAM }, encryptedBuffer);
  const plainText = arrayBufferToString(data);

  expect(plainText).to.deep.equal("A Healthier Life is a Happier Life");
});

it("BRITNEY: deriveKey value should match the value on the contract", async () => {
  const code = "7i6XA2zz";
  const pin = "qmHuG263";
  const { key, iv } = deriveKey(code, pin, BRITNEY);
  const givenKeyBase64 = "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=";
  const givenIvBase64 = "aoiywBzTwYxzKQz45UxWaQ==";

  const keyBase64 = arrayBufferToBase64(key);
  const ivBase64 = arrayBufferToBase64(iv);

  expect(keyBase64).to.deep.equal(givenKeyBase64);
  expect(ivBase64).to.deep.equal(givenIvBase64);
});

it("BRITNEY: encrypted data should match the values on the contract", async () => {
  const message = "A Healthier Life is a Happier Life";
  const messageBuffer = stringToArrayBuffer(message);
  const code = "7i6XA2zz";
  const pin = "qmHuG263";
  const { data } = await encrypt(code, pin, messageBuffer);
  const dataBase64 = arrayBufferToBase64(data);

  expect(dataBase64).to.deep.equal(
    "1EkGWJAKP0BG2CAstCFcq8ysbOEvYwruJrrJUBRVGQMe8590wfdKge/jfKcLwEjFg7Q="
  );
});

it("BRITNEY: decrypted data should match the values on the contract", async () => {
  const resultKeyBase64 = "1v6YGdN6BW2AR1uEylOmjSwKu/kUr5qNYR42X0Che3U=";
  const resultIvBase64 = "aoiywBzTwYxzKQz45UxWaQ==";
  const encryptedDataBase64 =
    "1EkGWJAKP0BG2CAstCFcq8ysbOEvYwruJrrJUBRVGQMe8590wfdKge/jfKcLwEjFg7Q=";

  const key = base64ToArrayBuffer(resultKeyBase64);
  const iv = base64ToArrayBuffer(resultIvBase64);
  const encryptedBuffer = base64ToArrayBuffer(encryptedDataBase64);

  const data = await decrypt({ key, iv, version: BRITNEY }, encryptedBuffer);
  const plainText = arrayBufferToString(data);

  expect(plainText).to.deep.equal("A Healthier Life is a Happier Life");
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
