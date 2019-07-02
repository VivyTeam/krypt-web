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
import { CHARLIE_STATIC_SALT } from "../lib/constants";

const hexToArrayBuffer = hex => {
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
  // Shared constant contract values which should always be used for Charlie encryption
  const ORIGINAL_STRING = "MyVeryImportantData";
  const ENCRYPTED_PAYLOAD = stringToArrayBuffer(ORIGINAL_STRING);
  const PIN = "someRandomPin12345678";
  const BACKEND_SECRET = "someRandomBackendSecret";
  const BACKEND_SALT = "someRandomSecondSalt";
  const IV = stringToArrayBuffer("AAAAAAAAAAAAAAAA");

  const HEX_ENCRYPTED =
    "70caa3b9cf21a495a0bb8269c3b7908fdbf26832a2d81bda1d686ed1212085270df3ba";
  const FINGERPRINT_FILE =
    "charlie:21262f4bce9412a3321ef8511fc276d39075944fcec9806cdc1d9848d0db2c35";
  const FINGERPRINT_SECRET =
    "charlie:58c9d7da8beafcc58cd92e179e1276cd3a238d83265f82df11ead7585c86666c7a3b583c42ffab3c0eebf837bb841d44544289cd476770cc0c3be38974b04167";

  const secrets = hash(PIN + BACKEND_SECRET, BACKEND_SALT);
  const { key, fingerprintFile } = splitKeys(secrets);

  it("should match contract's encrypt value", async () => {
    const encryptedBytes = await encrypt(key, IV, ENCRYPTED_PAYLOAD);

    expect(arrayBufferToHex(encryptedBytes)).toEqual(HEX_ENCRYPTED);
  });

  it("should match contract's decrypt value", async () => {
    const encryptedBytes = hexToArrayBuffer(HEX_ENCRYPTED);
    const arrayBufferData = await decrypt(key, IV, encryptedBytes);

    expect(arrayBufferToString(arrayBufferData)).toEqual(ORIGINAL_STRING);
  });

  it("should match contract's fingerprint file value", () => {
    expect(fingerprintFile).toEqual(FINGERPRINT_FILE);
  });

  it("should match contract's fingerprint secret value", () => {
    const secret = hash(PIN, CHARLIE_STATIC_SALT);

    expect(fingerprint(secret)).toEqual(FINGERPRINT_SECRET);
  });
});
