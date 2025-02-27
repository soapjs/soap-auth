import jwt from "jsonwebtoken";
import { JwtService } from "../jwks.service";
import {
  InvalidIdTokenError,
} from "../../strategies/oauth2/oauth2.errors";


describe("JwtService", () => {
  let service;
  let mockConfig;
  const mockIdToken = "mock.id.token";

  beforeEach(() => {
    jest.clearAllMocks();
    mockConfig = {
      jwks: {
        jwksUri: "https://mock-jwks-uri.com",
        algorithms: ["RS256"],
        issuer: "mock-issuer",
        audience: "mock-client-id",
      },
    };
    service = new JwtService(mockConfig as any);
  });

  it("verify throws error if ID token structure is invalid", async () => {
    jest.spyOn(jwt, "decode").mockReturnValue(null);
    await expect(service.verify(mockIdToken)).rejects.toThrow(
      "Invalid ID Token structure."
    );
  });

  it("verify throws error if ID token is expired", async () => {
    jest.spyOn(jwt, "decode").mockReturnValue({ header: { kid: "mock-kid" } });
    jest
      .spyOn((service as any).client, "getSigningKey")
      .mockResolvedValue({ getPublicKey: () => "mock-public-key" });
    jest
      .spyOn(jwt, "verify")
      .mockReturnValue({ exp: Math.floor(Date.now() / 1000) - 10 } as any);

    await expect(service.verify(mockIdToken)).rejects.toThrow(
      InvalidIdTokenError
    );
  });
});
