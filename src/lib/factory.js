export default type => {
  const types = ["aes-gcm", "rsa-oaep"];
  type = type.toLowerCase();

  switch (type) {
    case "aes-gcm":
      return {
        generateKey: () =>
          window.crypto.subtle.generateKey(
            {
              name: "AES-GCM",
              length: 256
            },
            true,
            ["encrypt", "decrypt"]
          ),
        importKey: arrayBufferKey =>
          window.crypto.subtle.importKey(
            "raw",
            arrayBufferKey,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          ),
        exportKey: key => window.crypto.subtle.exportKey("raw", key),
        encrypt: (key, iv, data) =>
          window.crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv
            },
            key,
            data
          ),
        decrypt: (key, iv, data) =>
          window.crypto.subtle.decrypt(
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
        generateKey: (bits = 4096) =>
          window.crypto.subtle.generateKey(
            {
              name: "RSA-OAEP",
              modulusLength: bits,
              publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
              hash: { name: "SHA-256" }
            },
            false,
            ["encrypt", "decrypt"]
          ),
        importKey: arrayBufferKey =>
          window.crypto.subtle.importKey(
            "spki",
            arrayBufferKey,
            { name: "RSA-OAEP", hash: { name: "SHA-256" } },
            false,
            ["encrypt"]
          ),
        exportKey: publicKey =>
          window.crypto.subtle.exportKey("spki", publicKey),
        encrypt: (publicKey, arrayBuffer) =>
          window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            publicKey,
            arrayBuffer
          ),
        decrypt: (privateKey, arrayBuffer) =>
          window.crypto.subtle.decrypt(
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
