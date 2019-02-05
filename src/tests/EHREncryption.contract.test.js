import { decrypt } from "../lib/EHREncryption";
import {
  arrayBufferToString,
  base64ToArrayBuffer,
  privateKeyToArrayBuffer,
  toArrayBuffer
} from "../lib/utilities";

it("should decrypt a value, given a private key and cipher key. All values are encoded on base64. All values are taken the contract.", async () => {
  const key =
    "-----BEGIN PRIVATE KEY-----\n" +
    "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\n" +
    "cylXdobDY+9PyR94z8g8VVVEG9snVA==\n" +
    "-----END PRIVATE KEY-----\n";

  const keyBuffer = toArrayBuffer(key);

  const cipherKey = base64ToArrayBuffer(
    "eU6KAdHtFUtw0XO6ANfKowU9SaLxFx3ocGMfemTj99nFFm6qB1ChFPQUFL3lYTffqRPI+ogeth5TBDg6xe1zoSUDC80gq5t19a1vKxUsjsKAehX2XzH+L/gs6qIis8wlhEp1FLGY5h6sJDp7JtsRG77GjnTBAlUq9tWA2AI6vt6aWggYOYZTbNV8N+qVNlocy64eGGzxqsEdrnctVxzR+sYikrjmAPk0FoakIqKvu+lu4VMW/Pf76o0qn6Z2dPX6Y4uDXpeFjTM0LOWgP0ZhKLmvFRfLfgnMsDTCnBODJD4oxTQkoQOLo2rW/X2E2VU8ymAjBZybaSBvztcYRNYAIzSLdedX79lQSpA7ZLi139ae05UiecUrNAn5VCfl3sFgqLv6Lf0UmeY0/mOdLfkEKYCBisn5dQNArxp0yu+vWRa+May/Czla3aaLRZIq8gFMNJlJ395cuodWE0MaFOkiXCThwt37y04NJn+13coytsvCNsKdWxnIS2X5FSgmhDKq7E3b07/FKdmj6m6Uc3Z73kRIJpQRIseJo5OSBDHioByNcdJ/RzTCnYuHLHc0fbN17Zt5O9oZzoCtLVbzKeqxYxX+WOok6D78lD6lySHcC0plqRpFcI5YBa5dRT7shrzY0I6w0FR3Z5ADWJ9YDlxedCGsDlmFFl3gv4PoUd9psFk="
  );
  const data = base64ToArrayBuffer(
    "8ISiEz9Gc8VWjBM3YuvOGeXIA7PXygu79HSKDxIRFxsibKAbgCYRSBPDlFVK6m7hMO0="
  );

  const privateKey = await window.crypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    { name: "RSA-OAEP", hash: { name: "SHA-256" } },
    false,
    ["decrypt"]
  );

  const decrypted = await decrypt(privateKey, { cipherKey, data });

  const string = arrayBufferToString(decrypted);

  expect(string).to.deep.equal("A Healthier Life is a Happier Life");
});
