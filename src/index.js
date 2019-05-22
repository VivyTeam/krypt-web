import create from "./lib/factory";

export { create };

export {
  decrypt as ehrDecrypt,
  encrypt as ehrEncrypt
} from "./lib/EHREncryption";
export {
  decrypt as medDecrypt,
  accessSignature as medAccessSignature,
  deriveKey as medDeriveKey
} from "./lib/MedStickerEncryption";

export {
  toPem,
  toArrayBuffer,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  generateInitialVector
} from "./lib/utilities";
