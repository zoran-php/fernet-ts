import '@testing-library/jest-dom';
import crypto from 'crypto';
import { Algorithms } from '../src/enums/Algorithms';
import { HashAlgorithm } from '../src/enums/HashAlgorithm';
import { importKey } from '../src/utils/crypto';

Object.defineProperty(global.self, 'crypto', {
  value: {
    subtle: crypto.webcrypto.subtle,
  },
});

describe('importKey', () => {
  test('returns a CryptoKey instance', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const key = await importKey(
      keyBytes,
      {
        name: Algorithms.HMAC,
        hash: HashAlgorithm.SHA256,
      },
      ['verify', 'sign']
    );
    expect(key.constructor.name).toEqual('CryptoKey');
  });

  test('returns CryptoKey with given algorithm name', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const usages: KeyUsage[] = ['verify', 'sign'];
    const key = await importKey(
      keyBytes,
      {
        name: Algorithms.HMAC,
        hash: HashAlgorithm.SHA256,
      },
      usages
    );
    expect(key.algorithm.name).toEqual(Algorithms.HMAC);
  });

  test('returns CryptoKey with given usages', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const usages: KeyUsage[] = ['verify', 'sign'];
    const key = await importKey(
      keyBytes,
      {
        name: Algorithms.HMAC,
        hash: HashAlgorithm.SHA256,
      },
      usages
    );
    expect(key.usages).toEqual(usages);
  });

  test('when given invalid algorithm name will throw an error', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const usages: KeyUsage[] = ['verify', 'sign'];
    await expect(
      importKey(
        keyBytes,
        {
          name: 'INVALID_ALGO',
        },
        usages
      )
    ).rejects.toThrowError('Unrecognized name.');
  });

  test('when given invalid usage will throw an error', async () => {
    const keyBytes = new Uint8Array([
      21, 31, 11, 1, 41, 51, 61, 71, 81, 91, 101, 111, 121, 4, 14, 24,
    ]);
    const usages: KeyUsage[] = ['verify', 'sign', 'encrypt'];
    await expect(
      importKey(
        keyBytes,
        {
          name: Algorithms.HMAC,
          hash: HashAlgorithm.SHA256,
        },
        usages
      )
    ).rejects.toThrowError('Unsupported key usage for an HMAC key');
  });
});
