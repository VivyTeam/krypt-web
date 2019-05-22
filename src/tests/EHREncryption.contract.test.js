import privateKey from "raw-loader!./contact-data/privateKey.pkcs8.pem"; // eslint-disable-line
import publicKey from "raw-loader!./contact-data/publicKey.spki.pem"; // eslint-disable-line
import { decrypt, encrypt } from "../lib/EHREncryption";
import {
  arrayBufferToString,
  base64ToArrayBuffer,
  stringToArrayBuffer,
  toArrayBuffer
} from "../lib/utilities";

describe("EHREncryption contract", () => {
  it("should decrypt a value, given a private key and cipher key. All values are encoded on base64. All values are taken the contract.", async () => {
    const keyBuffer = toArrayBuffer(privateKey);
    const cipherKey = base64ToArrayBuffer(
      "eU6KAdHtFUtw0XO6ANfKowU9SaLxFx3ocGMfemTj99nFFm6qB1ChFPQUFL3lYTffqRPI+ogeth5TBDg6xe1zoSUDC80gq5t19a1vKxUsjsKAehX2XzH+L/gs6qIis8wlhEp1FLGY5h6sJDp7JtsRG77GjnTBAlUq9tWA2AI6vt6aWggYOYZTbNV8N+qVNlocy64eGGzxqsEdrnctVxzR+sYikrjmAPk0FoakIqKvu+lu4VMW/Pf76o0qn6Z2dPX6Y4uDXpeFjTM0LOWgP0ZhKLmvFRfLfgnMsDTCnBODJD4oxTQkoQOLo2rW/X2E2VU8ymAjBZybaSBvztcYRNYAIzSLdedX79lQSpA7ZLi139ae05UiecUrNAn5VCfl3sFgqLv6Lf0UmeY0/mOdLfkEKYCBisn5dQNArxp0yu+vWRa+May/Czla3aaLRZIq8gFMNJlJ395cuodWE0MaFOkiXCThwt37y04NJn+13coytsvCNsKdWxnIS2X5FSgmhDKq7E3b07/FKdmj6m6Uc3Z73kRIJpQRIseJo5OSBDHioByNcdJ/RzTCnYuHLHc0fbN17Zt5O9oZzoCtLVbzKeqxYxX+WOok6D78lD6lySHcC0plqRpFcI5YBa5dRT7shrzY0I6w0FR3Z5ADWJ9YDlxedCGsDlmFFl3gv4PoUd9psFk="
    );
    const data = base64ToArrayBuffer(
      "8ISiEz9Gc8VWjBM3YuvOGeXIA7PXygu79HSKDxIRFxsibKAbgCYRSBPDlFVK6m7hMO0="
    );

    const cryptoKey = await window.crypto.subtle.importKey(
      "pkcs8",
      keyBuffer,
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      false,
      ["decrypt"]
    );

    const decrypted = await decrypt(cryptoKey, { cipherKey, data });

    const string = arrayBufferToString(decrypted);

    expect(string).toEqual("A Healthier Life is a Happier Life");
  });

  it("should encrypt a message, given a public key and decrypt it back given the contract key provided", async () => {
    const originalString = "A Healthier Life is a Happier Life";
    const buffer = stringToArrayBuffer(originalString);
    const publicKeyBuffer = toArrayBuffer(publicKey);
    const privateKeyBuffer = toArrayBuffer(privateKey);

    const cryptoPublicKey = await window.crypto.subtle.importKey(
      "spki",
      publicKeyBuffer,
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      false,
      ["encrypt"]
    );
    const cryptoPrivateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      privateKeyBuffer,
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      false,
      ["decrypt"]
    );

    const { cipherKey, data } = await encrypt(cryptoPublicKey, buffer);
    const arrayBufferData = await decrypt(cryptoPrivateKey, {
      cipherKey,
      data
    });

    expect(arrayBufferToString(arrayBufferData)).toEqual(originalString);
  });
});
