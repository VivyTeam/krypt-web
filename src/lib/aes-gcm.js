/*
  AES-GCM - generateKey
*/
export async function generateKey() {
  return await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
}

/*
  AES-GCM - importKey
*/
export async function importKey(rawKey) {
  return await window.crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );
}

/*
  AES-GCM - exportKey
*/
export async function exportKey(key) {
  return await window.crypto.subtle.exportKey("raw", key);
}

/*
  AES-GCM - encrypt
*/
export async function encrypt(key, iv, data) {
  return await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    data
  );
}

/*
  AES-GCM - decrypt
*/
export async function decrypt(key, iv, data) {
  return await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    key,
    data
  );
}
