import { randomBytes } from "crypto";
import { v4 as uuidv4 } from "uuid";

/**
 * Generates a secure random token for password reset purposes.
 * @returns {Promise<string>} The generated reset token.
 */
export const generateUUID = async (): Promise<string> => {
  return Promise.resolve(uuidv4());
};

/**
 * Generates a cryptographically secure random token for password reset purposes.
 * @returns {Promise<string>} The generated reset token.
 */
export const generateSecureToken = async (
  tokenLength = 32,
  encoding = "hex"
): Promise<string> => {
  return new Promise((resolve, reject) => {
    randomBytes(tokenLength, (err, buffer) => {
      if (err) return reject(err);
      resolve(buffer.toString(encoding as BufferEncoding));
    });
  });
};


export function resolveConfig<T>(
  strategyConfig: T | undefined,
  globalConfig: T | undefined
): T | undefined {
  return strategyConfig || globalConfig;
}