import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";

/**
 * Generates a secure random token for password reset purposes.
 * @returns {Promise<string>} The generated reset token.
 */
export const generateUUID = async (): Promise<string> => {
  return Promise.resolve(uuidv4());
};

export function resolveConfig<T>(
  strategyConfig: T | undefined,
  globalConfig: T | undefined
): T | undefined {
  return strategyConfig || globalConfig;
}

export const generateRandomString = (
  size = 32,
  encoding: BufferEncoding = "hex"
): string => {
  return crypto.randomBytes(size).toString(encoding);
};
