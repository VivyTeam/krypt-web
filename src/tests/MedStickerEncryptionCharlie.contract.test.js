import {
  encrypt,
  decrypt,
  hash,
  splitKeys,
  fingerprint
} from "../lib/MedStickerEncryptionCharlie";
import {
  arrayBufferToHex,
  arrayBufferToString,
  stringToArrayBuffer
} from "../lib/utilities";
import create from "../lib/factory";
import { CHARLIE_STATIC_SALT } from "../lib/constants";

const gcm = create("AES-GCM");

const hexToArrayBuffer = hex => {
  if (typeof hex !== "string") {
    throw new TypeError("Expected input to be a string");
  }

  if (hex.length % 2 !== 0) {
    throw new RangeError("Expected string to be an even number of characters");
  }

  const view = new Uint8Array(hex.length / 2);

  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }

  return view.buffer;
};

describe("test utilities ", () => {
  it("should convert hex string to ArrayBuffer", async () => {
    expect(hexToArrayBuffer("00010a10f0ff")).toEqual(
      new Uint8Array([0, 1, 10, 16, 240, 255]).buffer
    );
  });
});

describe("MedStickerEncryption contract, version charlie", () => {
  // these all are contract values given from the other sources to validate the encryption,
  // therefore are shared between out tests
  const originalString = "MyVeryImportantData";
  const fakePin = "someRandomPin12345678";
  const fakeBackendSecret = "someRandomBackendSecret";
  const fakeSecondSalt = "someRandomSecondSalt";
  const ivString = "AAAAAAAAAAAAAAAA";
  const encryptedHex =
    "70caa3b9cf21a495a0bb8269c3b7908fdbf26832a2d81bda1d686ed1212085270df3ba";

  const iv = stringToArrayBuffer(ivString);
  const hashed = hash(fakePin + fakeBackendSecret, fakeSecondSalt);

  it("should encrypt, transform result into hex, and match the contract's string", async () => {
    const { key } = splitKeys(hashed);
    const cryptoKey = await gcm.importKey(key);
    const bytesToEncrypt = stringToArrayBuffer(originalString);

    const encryptedBytes = await encrypt(cryptoKey, iv, bytesToEncrypt);

    expect(arrayBufferToHex(encryptedBytes)).toEqual(encryptedHex);
  });

  it("should decrypt, transform result into ArrayBuffer, and match the contract's string", async () => {
    const { key } = splitKeys(hashed);
    const cryptoKey = await gcm.importKey(key);
    const encryptedBytes = hexToArrayBuffer(encryptedHex);

    const arrayBufferData = await decrypt(cryptoKey, iv, encryptedBytes);

    expect(arrayBufferToString(arrayBufferData)).toEqual(originalString);
  });

  it("should split the result of the hash and compare it with the contract's string", () => {
    const { fingerprintFile } = splitKeys(hashed);
    expect(fingerprintFile).toEqual(
      "charlie:21262f4bce9412a3321ef8511fc276d39075944fcec9806cdc1d9848d0db2c35"
    );
  });

  it("should compare fingerprint with contract's string. Salt should be CHARLIE_STATIC_SALT", () => {
    const secret = hash(fakePin, CHARLIE_STATIC_SALT);
    expect(fingerprint(secret)).toEqual(
      "charlie:58c9d7da8beafcc58cd92e179e1276cd3a238d83265f82df11ead7585c86666c7a3b583c42ffab3c0eebf837bb841d44544289cd476770cc0c3be38974b04167"
    );
  });
});
