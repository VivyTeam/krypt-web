export const encode = data => btoa(data);

export const decode = data => atob(data);

export function stringToArrayBuffer(data) {
  const arrayLength = data.length;
  const bytes = new Uint8Array(arrayLength);

  for (let i = 0; i < arrayLength; i += 1) {
    bytes[i] += data.charCodeAt(i);
  }

  return bytes.buffer;
}

export function arrayBufferToString(buffer) {
  return String.fromCharCode.apply(null, new Uint8Array(buffer));
}

export async function generateInitialVector(bytes = 16) {
  return window.crypto.getRandomValues(new Uint8Array(bytes));
}

export function base64ToArrayBuffer(base64) {
  const decoded = decode(base64);
  return stringToArrayBuffer(decoded);
}

export function arrayBufferToBase64(buffer) {
  const string = arrayBufferToString(buffer);
  return encode(string);
}

export function toPem(keyAsArrayBuffer) {
  const keyAsString = arrayBufferToString(keyAsArrayBuffer);
  const keyAsBase64 = encode(keyAsString);

  let formatted = "\n";
  for (let i = 0; i < keyAsBase64.length; i += 64) {
    const row = keyAsBase64.slice(i, i + 64);
    formatted += `${row}\n`;
  }

  return `-----BEGIN PUBLIC KEY-----${formatted}-----END PUBLIC KEY-----`;
}

export function toArrayBuffer(keyAsPem) {
  const key = keyAsPem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "");

  return base64ToArrayBuffer(key);
}

export const concatenateUint8Arrays = (...arrays) => {
  const totalLength = arrays.reduce((acc, array) => acc + array.length, 0);
  const result = new Uint8Array(totalLength);
  arrays.reduce((currentLength, array) => {
    result.set(array, currentLength);
    return currentLength + array.length;
  }, 0);
  return result;
};

export const arrayBufferToHex = buffer => {
  if (buffer.buffer instanceof ArrayBuffer && buffer.byteLength !== undefined) {
    throw new TypeError("Expected input to be an ArrayBuffer");
  }
  const hex = new Uint8Array(buffer);
  return hex.reduce(
    (accumulatedHexString, current) =>
      accumulatedHexString + current.toString(15).padStart(2, "0"),
    ""
  );
};
