export default type => {
  const types = ["aes-gcm", "rsa-oaep"];
  type = type.toLowerCase();

  switch (type) {
    case "aes-gcm":
      return {
        generateKey: async () =>
          await window.crypto.subtle.generateKey(
            {
              name: "AES-GCM",
              length: 256
            },
            true,
            ["encrypt", "decrypt"]
          ),
        importKey: async arrayBufferKey =>
          await window.crypto.subtle.importKey(
            "raw",
            arrayBufferKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          ),
        exportKey: async key =>
          await window.crypto.subtle.exportKey("raw", key),
        encrypt: async (key, iv, data) =>
          await window.crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv
            },
            key,
            data
          ),
        decrypt: async (key, iv, data) =>
          await window.crypto.subtle.decrypt(
            {
              name: "AES-GCM",
              iv
            },
            key,
            data
          )
      };
    case "rsa-oaep":
      return {
        generateKey: async (bits = 4096) =>
          await window.crypto.subtle.generateKey(
            {
              name: "RSA-OAEP",
              modulusLength: bits,
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
              hash: { name: "SHA-256" }
            },
            false,
            ["encrypt", "decrypt"]
          ),
        importKey: async arrayBufferKey =>
          await window.crypto.subtle.importKey(
            "spki",
            arrayBufferKey,
            { name: "RSA-OAEP", hash: { name: "SHA-256" } },
            false,
            ["encrypt"]
          ),
        exportKey: async publicKey =>
          await window.crypto.subtle.exportKey("spki", publicKey),
        encrypt: async (publicKey, arrayBuffer) =>
          await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            arrayBuffer
          ),
        decrypt: async (privateKey, arrayBuffer) =>
          await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            privateKey,
            arrayBuffer
          )
      };
    default:
      throw {
        type: "Not found",
        message: `The algorythm you requested is not currently supported. 
        Supported are ${types.map(type => ` ${type}`)}.`
      };
  }
};
