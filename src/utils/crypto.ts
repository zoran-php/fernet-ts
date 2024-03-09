export function fromBase64Url(base64url: string): Uint8Array {
  return Uint8Array.from(
    globalThis.atob(base64url.replace(/_/g, '/').replace(/-/g, '+')),
    (c) => c.charCodeAt(0)
  );
}

export function toBase64Url(bytes: Uint8Array): string {
  let chars: string[] = [];
  bytes.forEach((byte) => {
    chars.push(String.fromCharCode(byte));
  });
  return globalThis
    .btoa(chars.join(''))
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

export function getRandomBytes(length: number): Uint8Array {
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  return randomBytes;
}

export async function importKey(
  key: Uint8Array,
  algo: Algorithm | HmacImportParams,
  keyUsages: KeyUsage[]
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', key, algo, false, keyUsages);
}

export async function generateHMAC(
  message: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign('HMAC', key, message);
  return new Uint8Array(signature);
}

export async function verifyHMAC(
  message: Uint8Array,
  key: CryptoKey,
  hmac: Uint8Array
): Promise<boolean> {
  let result = await crypto.subtle.verify('HMAC', key, hmac, message);
  return result;
}

export async function aesCbcEncrypt(
  plainText: string,
  iv: Uint8Array,
  key: CryptoKey
): Promise<Uint8Array> {
  const textBuffer = new TextEncoder().encode(plainText);
  const encryptedMessage = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    key,
    textBuffer
  );
  return new Uint8Array(encryptedMessage);
}

export async function aesCbcDecrypt(
  cipherText: Uint8Array,
  iv: Uint8Array,
  key: CryptoKey
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv,
    },
    key,
    cipherText
  );
  const plainText = new TextDecoder().decode(decrypted);
  return plainText;
}
