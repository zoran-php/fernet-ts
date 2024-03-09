import { describe, test, expect } from 'vitest';
import { algorithms } from '../src/enums/Algorithms';
import { hashAlgorithm } from '../src/enums/HashAlgorithm';
import { aesCbcDecrypt, aesCbcEncrypt, importKey } from '../src/utils/crypto';

describe('aesCbcEncrypt', () => {
  test('returns encrypted ciphertext as Uint8Array if the key and iv are valid', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 7,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const message = 'hello world';
    const ciphertext = await aesCbcEncrypt(message, iv, key);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length % 16).toBe(0);
  });

  test('returns encrypted ciphertext that is different from input', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 7,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const message = 'hello world';
    const ciphertext = await aesCbcEncrypt(message, iv, key);
    expect(ciphertext).not.toEqual(new TextEncoder().encode(message));
  });

  test('with given invalid iv throws an error', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const message = 'hello world';
    await expect(aesCbcEncrypt(message, iv, key)).rejects.toThrowError(
      'algorithm.iv must contain exactly 16 bytes'
    );
  });

  test('with given invalid key throws an error', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 8,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 89,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['sign', 'verify']
    );
    const message = 'hello world';
    await expect(aesCbcEncrypt(message, iv, key)).rejects.toThrowError(
      'The requested operation is not valid for the provided key'
    );
  });

  test('throws error with with key without encryption usage', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 8,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 89,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['decrypt']
    );
    const message = 'hello world';
    await expect(aesCbcEncrypt(message, iv, key)).rejects.toThrowError(
      'The requested operation is not valid for the provided key'
    );
  });
});

describe('aesCbcDecrypt', () => {
  test('returns decrypted plain text if the iv and key are valid', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 7,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const message = 'hello world';
    const ciphertext = await aesCbcEncrypt(message, iv, key);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length % 16).toBe(0);
    const plainText = await aesCbcDecrypt(ciphertext, iv, key);
    expect(plainText).toEqual(message);
  });

  test('throws an error if the iv is not valid', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 7,
    ]);
    const iv2 = new Uint8Array([
      13, 34, 76, 65, 90, 47, 29, 3, 40, 79, 40, 28, 55, 100, 3, 82,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const message = 'hello world';
    const ciphertext = await aesCbcEncrypt(message, iv, key);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length % 16).toBe(0);

    await expect(aesCbcDecrypt(ciphertext, iv2, key)).rejects.toThrowError(
      'The operation failed for an operation-specific reason'
    );
  });

  test('throws an error if the key is not valid', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 7,
    ]);
    const keyBytes2 = new Uint8Array([
      13, 34, 76, 65, 90, 47, 29, 3, 40, 79, 40, 28, 55, 100, 3, 82,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const key2 = await importKey(
      keyBytes2,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt', 'decrypt']
    );
    const message = 'hello world';
    const ciphertext = await aesCbcEncrypt(message, iv, key);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length % 16).toBe(0);

    await expect(aesCbcDecrypt(ciphertext, iv, key2)).rejects.toThrowError(
      'The operation failed for an operation-specific reason'
    );
  });

  test('throws an error if the key usage does not include decrypt', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const iv = new Uint8Array([
      45, 12, 67, 84, 13, 8, 39, 92, 101, 25, 56, 66, 32, 120, 113, 7,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.AES_CBC,
      },
      ['encrypt']
    );
    const message = 'hello world';
    const ciphertext = await aesCbcEncrypt(message, iv, key);
    expect(ciphertext).toBeInstanceOf(Uint8Array);
    expect(ciphertext.length % 16).toBe(0);

    await expect(aesCbcDecrypt(ciphertext, iv, key)).rejects.toThrowError(
      'The requested operation is not valid for the provided key'
    );
  });
});
