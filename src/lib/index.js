import {
  encrypt as medEncrypt,
  decrypt as medDecrypt,
  accessSignature as medAccessSignature,
  deriveKey as medDeriveKey
} from "./MedStickerEncryption";

export default { medEncrypt, medDecrypt, medAccessSignature, medDeriveKey };
