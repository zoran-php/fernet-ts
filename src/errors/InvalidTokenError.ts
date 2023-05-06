/**
 * InvalidTokenError class
 * @extends {Error}
 */
export class InvalidTokenError extends Error {
  /**
   * InvalidTokenError class constructor
   * @constructor
   * @param {string} message
   */
  constructor(message: string) {
    super(message);
  }
}
