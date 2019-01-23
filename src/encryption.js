'use strict';
export async function getCryptoKey() {
  const loaded = await db.getDBData(db.CRYPTO_TABLE);

  if (loaded) {
    const { data } = loaded;
    const { publicKey } = data;

    return keyBufferToPEM(publicKey);
  }

  const { key, publicKey } = await generateKey();
  await db.addDBData(db.CRYPTO_TABLE, { key, publicKey });

  return keyBufferToPEM(publicKey);
}

export function decrypt(cipherBase64, encrypted) {
  return Observable.from(db.getDBData(db.CRYPTO_TABLE)).pipe(
    flatMap(({ data }) => getKeyIVPair(data.key.privateKey, cipherBase64)),
    flatMap(({ key, iv }) => decryptData(key, iv, encrypted))
  );
}
