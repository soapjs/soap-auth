import { createHmac, randomBytes } from "crypto";

const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(str: string): Buffer {
  const s = str.replace(/=+$/, "").toUpperCase();
  const bytes: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of s) {
    const idx = BASE32_CHARS.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(key: Buffer, counter: bigint, digits: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter);
  const hmac = createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % 10 ** digits).padStart(digits, "0");
}

export interface TotpOptions {
  /** Time step in seconds. Default: 30 */
  step?: number;
  /** Number of OTP digits. Default: 6 */
  digits?: number;
  /** Number of past/future windows to accept. Default: 1 */
  window?: number;
}

/**
 * RFC 6238 Time-based One-Time Password (TOTP) service.
 *
 * Generates and verifies TOTP codes compatible with Google Authenticator,
 * Authy, and any other RFC 6238 compliant app. No external dependencies —
 * uses Node's built-in `crypto` module.
 *
 * Usage:
 * ```ts
 * const totp = new TotpService();
 * const secret = totp.generateSecret();         // share with user / QR code
 * const code   = totp.generateOTP(secret);      // for testing
 * const valid  = totp.verifyOTP(secret, code);  // true
 * const uri    = totp.generateQRUri(secret, 'MyApp', 'user@example.com');
 * ```
 */
export class TotpService {
  private readonly step: number;
  private readonly digits: number;
  private readonly window: number;

  constructor(options: TotpOptions = {}) {
    this.step = options.step ?? 30;
    this.digits = options.digits ?? 6;
    this.window = options.window ?? 1;
  }

  /**
   * Generates a cryptographically random base32 TOTP secret.
   * @param byteLength - Entropy in bytes (default 20 = 160 bits, RFC recommendation).
   */
  generateSecret(byteLength = 20): string {
    return base32Encode(randomBytes(byteLength));
  }

  /**
   * Generates a TOTP code for `secret` at the given timestamp (default: now).
   */
  generateOTP(secret: string, timestamp = Date.now()): string {
    const key = base32Decode(secret);
    const counter = BigInt(Math.floor(timestamp / 1000 / this.step));
    return hotp(key, counter, this.digits);
  }

  /**
   * Verifies a TOTP code, accepting codes from the current window ± `this.window` steps.
   * Returns `true` if the code is valid.
   */
  verifyOTP(secret: string, code: string, timestamp = Date.now()): boolean {
    if (!/^\d+$/.test(code) || code.length !== this.digits) return false;

    const key = base32Decode(secret);
    const counter = BigInt(Math.floor(timestamp / 1000 / this.step));

    for (let delta = -this.window; delta <= this.window; delta++) {
      const expected = hotp(key, counter + BigInt(delta), this.digits);
      if (expected === code) return true;
    }
    return false;
  }

  /**
   * Returns an `otpauth://` URI that can be encoded as a QR code for authenticator apps.
   *
   * @param secret  - The base32 TOTP secret.
   * @param issuer  - The application/service name shown in the authenticator.
   * @param account - The user's account label (email or username).
   */
  generateQRUri(secret: string, issuer: string, account: string): string {
    const params = new URLSearchParams({
      secret,
      issuer,
      algorithm: "SHA1",
      digits: String(this.digits),
      period: String(this.step),
    });
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
    return `otpauth://totp/${label}?${params.toString()}`;
  }

  /**
   * Generates `count` random backup codes (10 chars each, alphanumeric).
   * Callers are responsible for hashing/storing these before returning them.
   */
  generateBackupCodes(count = 8): string[] {
    return Array.from({ length: count }, () =>
      randomBytes(6).toString("hex").toUpperCase()
    );
  }
}
