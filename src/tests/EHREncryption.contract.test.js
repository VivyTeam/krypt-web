import { decrypt } from "../lib/EHREncryption";
import {
  arrayBufferToString,
  base64ToArrayBuffer,
  privateKeyToArrayBuffer,
  toArrayBuffer
} from "../lib/utilities";
import { privateKey as key } from "./key.json";

it("should decrypt a value, given a private key and cipher key. All values are encoded on base64. All values are taken the contract.", async () => {
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
