import { PKCEConfig } from "../../types";
import { PKCEService } from "../pkce.service";

class InMemoryPKCEPersistence {
  private storeMap = new Map<string, { expiration?: number }>();

  async store(key: string, meta?: any) {
    this.storeMap.set(key, meta || {});
  }

  async read(verifierOrChallenge: string) {
    return this.storeMap.get(verifierOrChallenge);
  }

  async remove(key: string) {
    this.storeMap.delete(key);
  }
}

describe("PKCEService", () => {
  let service: PKCEService<any>;
  let config: PKCEConfig<any>;

  beforeEach(() => {
    config = {
      verifier: {
        expiresIn: 1,
        embed: jest.fn(),
        extract: jest.fn().mockImplementation((ctx) => ctx.verifier),
        persistence: new InMemoryPKCEPersistence(),
      },
      challenge: {
        expiresIn: 1,
        embed: jest.fn(),
        extract: jest.fn().mockImplementation((ctx) => ctx.challenge),
        persistence: new InMemoryPKCEPersistence(),
      },
    };

    service = new PKCEService(config);
  });

  it("should generate and store a code verifier", async () => {
    const context = { key: "code_verifier_test" };
    const verifier = await service.generateCodeVerifier(context);

    expect(verifier).toBeDefined();

    expect(config.verifier.embed).toHaveBeenCalledWith(context, verifier);
  });

  it("should generate and store a code challenge", async () => {
    const context = { key: "code_challenge_test" };
    const challenge = await service.generateCodeChallenge(
      "test_verifier",
      context
    );

    expect(challenge).toBeDefined();
    expect(config.challenge.embed).toHaveBeenCalledWith(context, challenge);
  });

  it("should detect expired code verifier", async () => {
    config.verifier.embed = (ctx, cv) => {
      ctx.verifier = cv;
    };
    const context = { key: "expired_verifier_test" };
    await service.generateCodeVerifier(context);
    await new Promise((resolve) => setTimeout(resolve, 1500));

    const isExpired = await service.isCodeVerifierExpired(context);
    expect(isExpired).toBe(true);
  });

  it("should detect not-expired code verifier", async () => {
    config.verifier.embed = (ctx, cv) => {
      ctx.verifier = cv;
    };
    const context = {
      key: "not_expired_verifier_test",
    };
    await service.generateCodeVerifier(context);
    await new Promise((resolve) => setTimeout(resolve, 500));

    const isExpired = await service.isCodeVerifierExpired(context);
    expect(isExpired).toBe(false);
  });

  it("should clear code verifier", async () => {
    const context = {
      key: "clear_verifier_test",
      verifier: "test_verifier_value",
    };
    await service.clearCodeVerifier(context);
  });
});
