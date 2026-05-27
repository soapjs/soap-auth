import crypto from "crypto";

export const generateUUID = async (): Promise<string> => {
  return Promise.resolve(crypto.randomUUID());
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
