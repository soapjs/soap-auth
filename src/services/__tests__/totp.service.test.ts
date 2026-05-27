import { TotpService } from "../totp.service";

describe("TotpService", () => {
  const totp = new TotpService();

  describe("generateSecret", () => {
    it("returns a non-empty base32 string", () => {
      const secret = totp.generateSecret();
      expect(secret).toMatch(/^[A-Z2-7]+$/);
      expect(secret.length).toBeGreaterThan(0);
    });

    it("returns unique secrets", () => {
      const a = totp.generateSecret();
      const b = totp.generateSecret();
      expect(a).not.toBe(b);
    });
  });

  describe("generateOTP", () => {
    it("returns a 6-digit string for a fixed timestamp", () => {
      const secret = totp.generateSecret();
      const code = totp.generateOTP(secret, 1000000000000);
      expect(code).toMatch(/^\d{6}$/);
    });

    it("returns the same code within the same time step", () => {
      const secret = totp.generateSecret();
      const ts = 1000000000000;
      expect(totp.generateOTP(secret, ts)).toBe(totp.generateOTP(secret, ts + 5000));
    });

    it("returns a different code in a different time step", () => {
      const secret = totp.generateSecret();
      const ts = 1000000000000;
      const code1 = totp.generateOTP(secret, ts);
      const code2 = totp.generateOTP(secret, ts + 30_000);
      expect(code1).not.toBe(code2);
    });
  });

  describe("verifyOTP", () => {
    it("accepts a valid code at the current timestamp", () => {
      const secret = totp.generateSecret();
      const ts = Date.now();
      const code = totp.generateOTP(secret, ts);
      expect(totp.verifyOTP(secret, code, ts)).toBe(true);
    });

    it("accepts a code one step in the past (window = 1)", () => {
      const secret = totp.generateSecret();
      const ts = 1000000000000;
      const pastCode = totp.generateOTP(secret, ts - 30_000);
      expect(totp.verifyOTP(secret, pastCode, ts)).toBe(true);
    });

    it("accepts a code one step in the future (window = 1)", () => {
      const secret = totp.generateSecret();
      const ts = 1000000000000;
      const futureCode = totp.generateOTP(secret, ts + 30_000);
      expect(totp.verifyOTP(secret, futureCode, ts)).toBe(true);
    });

    it("rejects a code two steps old when window = 1", () => {
      const secret = totp.generateSecret();
      const ts = 1000000000000;
      const oldCode = totp.generateOTP(secret, ts - 60_000);
      expect(totp.verifyOTP(secret, oldCode, ts)).toBe(false);
    });

    it("rejects an invalid code", () => {
      const secret = totp.generateSecret();
      expect(totp.verifyOTP(secret, "000000", Date.now())).toBe(false);
    });

    it("rejects non-numeric input", () => {
      const secret = totp.generateSecret();
      expect(totp.verifyOTP(secret, "abcdef")).toBe(false);
    });

    it("rejects wrong-length input", () => {
      const secret = totp.generateSecret();
      expect(totp.verifyOTP(secret, "12345")).toBe(false);
    });
  });

  describe("custom options", () => {
    it("generates 8-digit codes when configured", () => {
      const t8 = new TotpService({ digits: 8 });
      const secret = t8.generateSecret();
      const code = t8.generateOTP(secret);
      expect(code).toMatch(/^\d{8}$/);
    });

    it("accepts window = 0 — only the current step", () => {
      const t0 = new TotpService({ window: 0 });
      const secret = t0.generateSecret();
      const ts = 1000000000000;
      const pastCode = t0.generateOTP(secret, ts - 30_000);
      expect(t0.verifyOTP(secret, pastCode, ts)).toBe(false);
      const current = t0.generateOTP(secret, ts);
      expect(t0.verifyOTP(secret, current, ts)).toBe(true);
    });
  });

  describe("generateQRUri", () => {
    it("returns a valid otpauth URI", () => {
      const secret = totp.generateSecret();
      const uri = totp.generateQRUri(secret, "MyApp", "user@example.com");
      expect(uri).toMatch(/^otpauth:\/\/totp\//);
      expect(uri).toContain(secret);
      expect(uri).toContain("issuer=MyApp");
    });
  });

  describe("generateBackupCodes", () => {
    it("returns 8 codes by default", () => {
      const codes = totp.generateBackupCodes();
      expect(codes).toHaveLength(8);
    });

    it("returns the requested count", () => {
      const codes = totp.generateBackupCodes(10);
      expect(codes).toHaveLength(10);
    });

    it("returns uppercase hex strings of 12 chars", () => {
      const codes = totp.generateBackupCodes();
      codes.forEach((c) => expect(c).toMatch(/^[0-9A-F]{12}$/));
    });

    it("returns unique codes", () => {
      const codes = totp.generateBackupCodes(20);
      const unique = new Set(codes);
      expect(unique.size).toBe(20);
    });
  });
});
