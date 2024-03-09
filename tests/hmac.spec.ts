import { describe, test, expect } from 'vitest';
import { algorithms } from '../src/enums/Algorithms';
import { hashAlgorithm } from '../src/enums/HashAlgorithm';
import { generateHMAC, importKey, verifyHMAC } from '../src/utils/crypto';

describe('generateHMAC', () => {
  test('returns a 32-byte long Uint8Array', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const message = 'hello world';
    const messageBuffer = new TextEncoder().encode(message);
    const hmac = await generateHMAC(messageBuffer, key);
    expect(hmac.length).toEqual(32);
  });

  test('always returns the same 32-byte long Uint8Array output for the same input and key', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const message = 'hello world';
    const messageBuffer = new TextEncoder().encode(message);
    const hmac1 = await generateHMAC(messageBuffer, key);
    const hmac2 = await generateHMAC(messageBuffer, key);
    const hmac3 = await generateHMAC(messageBuffer, key);
    expect(hmac1.buffer).toEqual(hmac2.buffer);
    expect(hmac1.buffer).toEqual(hmac3.buffer);
    expect(hmac2.buffer).toEqual(hmac3.buffer);
  });
});

describe('verifyHMAC', () => {
  test('returns true for the valid signature', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const message = 'hello world';
    const messageBuffer = new TextEncoder().encode(message);
    const hmac = await generateHMAC(messageBuffer, key);
    const isVerified = await verifyHMAC(messageBuffer, key, hmac);
    expect(isVerified).toBe(true);
  });

  test('returns false for the invalid signature', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const message = 'hello world';
    const messageBuffer = new TextEncoder().encode(message);
    const hmac = await generateHMAC(messageBuffer, key);
    const isVerified = await verifyHMAC(
      messageBuffer,
      key,
      new Uint8Array([21, 31, 11, 1, 41, 51, 61])
    );
    expect(isVerified).toBe(false);
  });

  test('returns false for the invalid message', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const message = 'hello world';
    const messageBuffer = new TextEncoder().encode(message);
    const hmac = await generateHMAC(messageBuffer, key);
    const isVerified = await verifyHMAC(
      new Uint8Array([21, 31, 11, 1, 41, 51, 61]),
      key,
      hmac
    );
    expect(isVerified).toBe(false);
  });

  test('returns false for the invalid key', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const secondKeyBytes = new Uint8Array([
      45, 12, 98, 41, 23, 3, 19, 23, 76, 41, 58, 120, 29, 54, 73, 80,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const secondKey = await importKey(
      secondKeyBytes,
      {
        name: algorithms.HMAC,
        hash: hashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );

    const message = 'hello world';
    const messageBuffer = new TextEncoder().encode(message);
    const hmac = await generateHMAC(messageBuffer, key);
    const isVerified = await verifyHMAC(messageBuffer, secondKey, hmac);
    expect(isVerified).toBe(false);
  });
});
