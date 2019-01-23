
export async function generateKey(bits = 4096) {
  // Generate the RSA-OAEP 4096 bit Keys using SHA-256 Algorithms
  const key = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" }
    },
    false,
    ["encrypt", "decrypt"]
  );

  const publicKey = await window.crypto.subtle.exportKey("spki", key.publicKey);

  return { key, publicKey };
}

export async function getKeyIVPair(privateKey, cipher) {
  const decoded = window.atob(cipher);
  const buffer = stringToArrayBuffer(decoded);

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP"
    },
    privateKey,
    buffer
  );

  const envelope = arrayBufferToString(decrypted);
  const { base64EncodedKey, base64EncodedIV } = JSON.parse(envelope);
  const key = stringToArrayBuffer(window.atob(base64EncodedKey));
  const iv = stringToArrayBuffer(window.atob(base64EncodedIV));

  return { key, iv };
}

export async function decryptData(key, iv, data) {
  const importedKey = await window.crypto.subtle.importKey(
    "raw",
    key,
    {
      name: "AES-GCM"
    },
    false,
    ["decrypt"]
  );

  return window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    importedKey,
    data
  );
}
