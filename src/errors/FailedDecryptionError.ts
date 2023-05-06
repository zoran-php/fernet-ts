/**
 * InvalidSecretError class
 * @extends {Error}
 */
export class FailedDecryptionError extends Error {
  /**
   * InvalidSecretError class constructor
   * @constructor
   * @param {string} message
   */
  constructor(message: string) {
    super(message);
  }
}
