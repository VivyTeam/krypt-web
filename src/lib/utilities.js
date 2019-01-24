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

export async function generateInitialVector(bytes = 12) {
  return await window.crypto.getRandomValues(new Uint8Array(bytes));
}

export function toPem(keyAsArrayBuffer) {
  const keyAsString = arrayBufferToString(keyAsArrayBuffer);
  const keyAsBase64 = window.btoa(keyAsString);
  var formatted = sliceInRows(keyAsBase64);

  return `-----BEGIN PUBLIC KEY-----${formatted}-----END PUBLIC KEY-----`;
}

export function toArrayBuffer(keyAsPem) {
  let key;
  key = keyAsPem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "");

  const string = window.atob(key);
  return stringToArrayBuffer(string);
}

function sliceInRows(keyAsBase64) {
  let finalString = "\n";
  for (let i = 0; i < keyAsBase64.length; i += 64) {
    const row = keyAsBase64.slice(i, i + 64);
    finalString += `${row}\n`;
  }

  return finalString;
}
