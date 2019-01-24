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

// this stills need to be tested and used. just ignore for now.
export function keyBufferToPEM(keyBuffer) {
  const exportedAsString = arrayBufferToString(keyBuffer);
  const exportedAsBase64 = window.btoa(exportedAsString);
  return `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
}
