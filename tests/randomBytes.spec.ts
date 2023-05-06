import '@testing-library/jest-dom';
import { TextEncoder } from 'util';
import { getRandomBytes } from '../src/utils/crypto';

global.TextEncoder = TextEncoder;

function getRandomInt(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min) + min); // The maximum is exclusive and the minimum is inclusive
}

describe('getRandomBytes', () => {
  test('returns a Uint8Array instance', () => {
    const length = getRandomInt(1, 99);
    const result = getRandomBytes(length);
    expect(result).toBeInstanceOf(Uint8Array);
  });

  test('returns a Uint8Array whose length is equal as provided length param', () => {
    const length = getRandomInt(1, 99);
    const result = getRandomBytes(length);
    expect(result.length).toEqual(length);
  });

  test('returns a random Uint8Array', () => {
    const length = getRandomInt(1, 99);
    const resultOne = getRandomBytes(length);
    const resultTwo = getRandomBytes(length);
    expect(resultOne.buffer).not.toStrictEqual(resultTwo.buffer);
  });
});
