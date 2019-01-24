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
