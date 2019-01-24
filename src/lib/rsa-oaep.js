/*
  RSA-OAEP - generateKey
*/
export async function generateKey(bits = 4096) {
  return await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" }
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/*
  RSA-OAEP - encrypt
*/
export async function encrypt(publicKey, buffer) {
  return await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    buffer
  );
}

/*
  RSA-OAEP - decrypt
*/
export async function decrypt(privateKey, buffer) {
  return await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    buffer
  );
}
