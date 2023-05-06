import { Algorithms } from './enums/Algorithms';
import { HashAlgorithm } from './enums/HashAlgorithm';
import { FailedDecryptionError } from './errors/FailedDecryptionError';
import { InvalidSecretError } from './errors/InvalidSecretError';
import { InvalidTokenError } from './errors/InvalidTokenError';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  fromBase64Url,
  generateHMAC,
  getRandomBytes,
  importKey,
  toBase64Url,
  verifyHMAC,
} from './utils/crypto';

/**
 * @class Fernet
 * @property {Function} encrypt {@link Fernet.encrypt}
 * @property {Function} decrypt {@link Fernet.decrypt}
 */
export class Fernet {
  /**
   * @constructor
   * @private
   * @param {CryptoKey} signingKey
   * @param {CryptoKey} encryptionKey
   */
  private constructor(
    private signingKey: CryptoKey,
    private encryptionKey: CryptoKey
  ) {}

  /**
   * Creates and returns new Fernet instance
   *
   * @author Zoran Davidovic
   * @method
   * @public
   * @static
   * @async
   * @param {string} secretKey
   * @returns {Promise<Fernet>} New Fernet Instance
   */
  static async getInstance(secretKey: string): Promise<Fernet> {
    const { signingKey, encryptionKey } = await Fernet.importKeys(secretKey);
    return new Fernet(signingKey, encryptionKey);
  }

  /**
   * Initializes signing and encryption key and returns them.
   *
   * @author Zoran Davidovic
   * @method
   * @private
   * @static
   * @async
   * @name initializeKeys
   * @returns {Promise<{signingKey: CryptoKey, encryptionKey: CryptoKey}>} Signing and encryption key
   */
  private static async initializeKeys(
    secretKeyBuffer: Uint8Array
  ): Promise<{ signingKey: CryptoKey; encryptionKey: CryptoKey }> {
    const signingKeyBuffer = secretKeyBuffer.slice(0, 16);
    const encryptionKeyBuffer = secretKeyBuffer.slice(16);
    const [signingKey, encryptionKey] = await Promise.all([
      importKey(
        signingKeyBuffer,
        {
          name: Algorithms.HMAC,
          hash: HashAlgorithm.SHA256,
        },
        ['verify', 'sign']
      ),
      importKey(encryptionKeyBuffer, { name: Algorithms.AES_CBC }, [
        'encrypt',
        'decrypt',
      ]),
    ]);
    return { signingKey, encryptionKey };
  }

  /**
   * Converts key to Uint8Array, checks the length, imports the keys and returns new Fernet instance.
   * Throws InvalidSecretError if the secret is invalid.
   *
   * @author Zoran Davidovic
   * @method
   * @private
   * @static
   * @async
   * @name importKeys
   * @returns {Promise<Fernet>} New Fernet instance
   * @throws {InvalidSecretError} Invalid Secret Error
   */
  private static async importKeys(
    secretKey: string
  ): Promise<{ signingKey: CryptoKey; encryptionKey: CryptoKey }> {
    let keyBuffer = new Uint8Array();
    try {
      keyBuffer = fromBase64Url(secretKey);
    } catch (err) {
      throw new InvalidSecretError('Invalid secret key encoding.');
    }
    if (keyBuffer.length !== 32) {
      throw new InvalidSecretError('Invalid secret key length.');
    }
    return Fernet.initializeKeys(keyBuffer);
  }

  /**
   * Creates new current timestamp and returns Uint8Array containing that timestamp
   *
   * @author Zoran Davidovic
   * @method
   * @private
   * @static
   * @name getTimestampBuffer
   * @returns {Uint8Array} Uint8Array containing timestamp
   */
  private static getTimestampBuffer(): Uint8Array {
    const timeBuffer = new ArrayBuffer(8);
    const view = new DataView(timeBuffer);
    const currentTimeMs = Date.now();
    const unixEpochTime = Math.round(currentTimeMs / 1000);
    view.setBigUint64(0, BigInt(unixEpochTime), false);
    return new Uint8Array(timeBuffer);
  }

  /**
   * Encrypts plain text and returns Fernet Token
   *
   * @method
   * @author Zoran Davidovic
   * @name encrypt
   * @public
   * @async
   * @param {string} plainText
   * @returns {Promise<string>} Base64Url encoded Fernet token
   */
  async encrypt(plainText: string): Promise<string> {
    return Fernet.doEncryption(plainText, this.signingKey, this.encryptionKey);
  }

  /**
   * Encrypts plain text and returns Fernet Token
   *
   * @method encrypt
   * @author Zoran Davidovic
   * @name encrypt
   * @public
   * @static
   * @async
   * @param {string} plainText
   * @param {string} secretKey
   * @returns {Promise<string>} Base64Url encoded Fernet token
   */
  static async encrypt(plainText: string, secretKey: string): Promise<string> {
    const { signingKey, encryptionKey } = await Fernet.importKeys(secretKey);
    return Fernet.doEncryption(plainText, signingKey, encryptionKey);
  }

  /**
   * Encrypts plain text and returns Fernet Token
   *
   * @method doEncryption
   * @author Zoran Davidovic
   * @name doEncryption
   * @private
   * @static
   * @async
   * @param {string} plainText
   * @param {CryptoKey} signingKey
   * @param {CryptoKey} encryptionKey
   * @returns {Promise<string>} Base64Url encoded Fernet token
   */
  private static async doEncryption(
    plainText: string,
    signingKey: CryptoKey,
    encryptionKey: CryptoKey
  ): Promise<string> {
    const iv = getRandomBytes(16);
    const cipherText = await aesCbcEncrypt(plainText, iv, encryptionKey);
    const version = new Uint8Array([0x80]);
    const timestamp = Fernet.getTimestampBuffer();
    const unsignedToken = new Uint8Array([
      ...version,
      ...timestamp,
      ...iv,
      ...cipherText,
    ]);
    const hmac = await generateHMAC(unsignedToken, signingKey);
    const signedToken = new Uint8Array([...unsignedToken, ...hmac]);
    return toBase64Url(signedToken);
  }

  /**
   * Decrypts Fernet token and returns plain text
   *
   * @method
   * @throws {InvalidTokenError} - Invalid token error
   * @author Zoran Davidovic
   * @name decrypt
   * @public
   * @async
   * @param {string} fernetToken
   * @returns {Promise<string>} Decrypted plain text
   */
  async decrypt(fernetToken: string): Promise<string> {
    return Fernet.doDecryption(
      fernetToken,
      this.signingKey,
      this.encryptionKey
    );
  }

  /**
   * Decrypts Fernet token and returns plain text
   *
   * @method
   * @throws {InvalidTokenError} - Invalid token error
   * @author Zoran Davidovic
   * @name decrypt
   * @public
   * @static
   * @async
   * @param {string} fernetToken
   * @param {string} secretKey
   * @returns {Promise<string>} Decrypted plain text
   */
  static async decrypt(
    fernetToken: string,
    secretKey: string
  ): Promise<string> {
    const { signingKey, encryptionKey } = await Fernet.importKeys(secretKey);
    return Fernet.doDecryption(fernetToken, signingKey, encryptionKey);
  }

  /**
   * Decrypts Fernet token and returns plain text
   *
   * @method
   * @throws {InvalidTokenError} - Invalid token error
   * @author Zoran Davidovic
   * @name doDecryption
   * @private
   * @static
   * @async
   * @param {string} fernetToken
   * @param {CryptoKey} signingKey
   * @param {CryptoKey} encryptionKey
   * @returns {Promise<string>} Decrypted plain text
   */
  private static async doDecryption(
    fernetToken: string,
    signingKey: CryptoKey,
    encryptionKey: CryptoKey
  ): Promise<string> {
    let tokenBuffer = new Uint8Array();
    try {
      tokenBuffer = fromBase64Url(fernetToken);
    } catch (err) {
      throw new InvalidTokenError('Fernet token has invalid encoding.');
    }
    if (
      tokenBuffer.length < 73 ||
      (tokenBuffer.length - (1 + 8 + 16 + 32)) % 16 !== 0
    ) {
      throw new InvalidTokenError('Fernet token has invalid length.');
    }
    const version = tokenBuffer.slice(0, 1);
    const timestamp = tokenBuffer.slice(1, 9);
    const iv = tokenBuffer.slice(9, 25);
    const cipherText = tokenBuffer.slice(25, -32);
    const hmac = tokenBuffer.slice(-32);
    let plainText = '';
    try {
      plainText = await aesCbcDecrypt(cipherText, iv, encryptionKey);
    } catch (err) {
      throw new FailedDecryptionError('Failed to decrypt the ciphertext.');
    }
    const unsignedToken = tokenBuffer.slice(0, -32);
    const isTokenVerified = await verifyHMAC(unsignedToken, signingKey, hmac);
    if (!isTokenVerified) {
      throw new InvalidTokenError('Fernet token has invalid signature.');
    }
    return plainText;
  }

  /**
   * Generates random 32-bytes long secret encoded as base64url string
   * @author Zoran Davidovic
   * @public
   * @static
   * @returns {string} Base64Url encoded 32-byte secret
   */
  static generateSecret(): string {
    return toBase64Url(getRandomBytes(32));
  }
}
