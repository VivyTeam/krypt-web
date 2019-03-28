import create from "./factory";
import { decrypt as ehrDecrypt, encrypt as ehrEncrypt } from "./EHREncryption";
import {
  decrypt as medDecrypt,
  accessSignature as medAccessSignature,
  deriveKey as medDeriveKey
} from "./MedStickerEncryption";
import {
  toPem,
  toArrayBuffer,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  generateInitialVector
} from "./utilities";

export default {
  create,

  ehrEncrypt,
  ehrDecrypt,

  medDecrypt,
  medAccessSignature,
  medDeriveKey,

  arrayBufferToBase64,
  base64ToArrayBuffer,
  toPem,
  toArrayBuffer,
  generateInitialVector
};
