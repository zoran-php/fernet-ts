import '@testing-library/jest-dom';
import { Algorithms } from '../src/enums/Algorithms';
import { HashAlgorithm } from '../src/enums/HashAlgorithm';

describe('algorithms enum', () => {
  test('has AES-CBC algorithm', () => {
    const expected = 'AES-CBC';
    expect(Algorithms.AES_CBC).toEqual(expected);
  });

  test('has HMAC algorithm', () => {
    const expected = 'HMAC';
    expect(Algorithms.HMAC).toEqual(expected);
  });

  test('should pass', () => {
    expect(Algorithms).toMatchInlineSnapshot(`
      {
        "AES_CBC": "AES-CBC",
        "HMAC": "HMAC",
      }
    `);
  });
});

describe('hash algorithm enum', () => {
  test('has SHA-1 algorithm', () => {
    const expected = 'SHA-1';
    expect(HashAlgorithm.SHA1).toEqual(expected);
  });

  test('has SHA-256 algorithm', () => {
    const expected = 'SHA-256';
    expect(HashAlgorithm.SHA256).toEqual(expected);
  });

  test('has SHA-384 algorithm', () => {
    const expected = 'SHA-384';
    expect(HashAlgorithm.SHA384).toEqual(expected);
  });

  test('has SHA-512 algorithm', () => {
    const expected = 'SHA-512';
    expect(HashAlgorithm.SHA512).toEqual(expected);
  });

  test('should pass', () => {
    expect(HashAlgorithm).toMatchInlineSnapshot(`
        {
          "SHA1": "SHA-1",
          "SHA256": "SHA-256",
          "SHA384": "SHA-384",
          "SHA512": "SHA-512",
        }
      `);
  });
});
