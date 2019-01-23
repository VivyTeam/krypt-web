export function stringToArrayBuffer(data) {
  const arrayLength = data.length;
  const bytes = new Uint8Array(arrayLength);

  for (let i = 0; i < arrayLength; i += 1) {
    bytes[i] += data.charCodeAt(i);
  }

  console.log(bytes.buffer)
  return bytes.buffer;
}

export function arrayBufferToString(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);

  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return binary;
}

export function keyBufferToPEM(keyBuffer) {
  const bufferString = arrayBufferToString(keyBuffer);
  const base64Key = window.btoa(bufferString);
  let formatted = "";

  for (let i = 0; i < base64Key.length; i += 64) {
    const pemRow = base64Key.slice(i, i + 64);
    formatted += `${pemRow}\n`;
  }

  return `-----BEGIN PUBLIC KEY-----\n${formatted}-----END PUBLIC KEY-----`;
}
