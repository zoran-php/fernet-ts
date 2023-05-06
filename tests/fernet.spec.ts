import '@testing-library/jest-dom';
import crypto from 'crypto';
import { TextDecoder, TextEncoder } from 'util';
import { Fernet } from '../src/Fernet';
import {
  fromBase64Url,
  getRandomBytes,
  toBase64Url,
} from '../src/utils/crypto';

Object.assign(global, { TextDecoder, TextEncoder });

Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: crypto.webcrypto.subtle,
    getRandomValues: crypto.webcrypto.getRandomValues,
  },
});

describe('Ferent.generateSecret', () => {
  test('should return different secret every time', async () => {
    const secret1 = Fernet.generateSecret();
    const secret2 = Fernet.generateSecret();
    const secret3 = Fernet.generateSecret();
    expect(secret1).not.toEqual(secret2);
    expect(secret1).not.toEqual(secret3);
    expect(secret2).not.toEqual(secret3);
  });

  test('should return a valid secret', async () => {
    const secret = Fernet.generateSecret();
    expect(secret).toMatch(/^[A-Za-z0-9\-_=]{44}$/);
  });
});

describe('Ferent.getInstance', () => {
  test('should return new Fernet instance with the valid secret', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    expect(fernet).toBeInstanceOf(Fernet);
  });

  test('should throw an error if the key has invalid length', async () => {
    const secret = 'bG9yZW1pcHN1bQ';
    await expect(Fernet.getInstance(secret)).rejects.toThrowError(
      'Invalid secret key length.'
    );
  });

  test('should throw an error if the key has invalid encoding', async () => {
    const secret = '#$&(^$$#$$#@#%&**(&*()_?><:;}]{[!@#';
    await expect(Fernet.getInstance(secret)).rejects.toThrowError(
      'Invalid secret key encoding.'
    );
  });
});

describe('encrypt', () => {
  test('should return a Fernet token if the secret is valid', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    const message = 'hello world';
    const fernetToken = await fernet.encrypt(message);
    expect(fernetToken).not.toEqual(message);
    expect(typeof fernetToken).toBe('string');
  });
});

describe('decrypt', () => {
  test('should decrypt the encrypted fernet token', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    const message = 'hello world';
    const fernetToken = await fernet.encrypt(message);
    const decryptedText = await fernet.decrypt(fernetToken);
    expect(decryptedText).toEqual(message);
  });

  test('should throw an error if the token has invalid encoding', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    const fernetToken = 'invalid_token';
    await expect(fernet.decrypt(fernetToken)).rejects.toThrowError(
      'Fernet token has invalid encoding.'
    );
  });

  test('should throw an error if the token has invalid length', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    const fernetToken = 'bG9yZW1pcHN1bQ';
    await expect(fernet.decrypt(fernetToken)).rejects.toThrowError(
      'Fernet token has invalid length.'
    );
  });

  test('should throw an error if the encryption key is invalid', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    const message = 'hello world';
    const fernetToken = await fernet.encrypt(message);
    const invalidFernetToken =
      'gAAAAABkVkz28mAO6KAXylTYm6iN5xu5O0oUMQZYSu5b09bywGDj1_qI1X0tnSKUsUe0k5zeEazuVCfufXI-lxXaydvhRsnvhw==';
    await expect(fernet.decrypt(invalidFernetToken)).rejects.toThrowError(
      'Failed to decrypt the ciphertext.'
    );
  });

  test('should throw an error if the encryption key is invalid', async () => {
    const secret = Fernet.generateSecret();
    const fernet = await Fernet.getInstance(secret);
    const message = 'hello world';
    const fernetToken = await fernet.encrypt(message);
    const fernetTokenBuffer = fromBase64Url(fernetToken);
    const invalidSignature = getRandomBytes(32);
    const unsignedToken = fernetTokenBuffer.slice(0, -32);
    const signedInvalidTokenBuffer = new Uint8Array([
      ...unsignedToken,
      ...invalidSignature,
    ]);
    const tokenWithInvalidSignature = toBase64Url(signedInvalidTokenBuffer);
    await expect(
      fernet.decrypt(tokenWithInvalidSignature)
    ).rejects.toThrowError('Fernet token has invalid signature.');
  });
});
