import { OAuth2NonceConfig, OAuth2StrategyConfig } from "./oauth2.types";
import { generateRandomString } from "../../tools";

export class OAuth2Tools {
  static async generateState(config: OAuth2StrategyConfig): Promise<string> {
    return (await config.state?.generateState?.()) || generateRandomString();
  }

  static async generateNonce(config: OAuth2StrategyConfig): Promise<string> {
    return (await config.nonce?.generateNonce?.()) || generateRandomString();
  }

  static async validateNonce(
    expectedNonce: string,
    nonce: string,
    config: OAuth2NonceConfig
  ): Promise<boolean> {
    if (config.validateNonce) {
      return config.validateNonce(expectedNonce, nonce);
    }

    return expectedNonce === nonce;
  }

  static extractState<TContext>(context: TContext): string | null {
    return (context as any).query?.state || null;
  }

  static extractNonce(idToken: string): string | null {
    const decoded = JSON.parse(
      Buffer.from(idToken.split(".")[1], "base64").toString()
    );
    return decoded.nonce || null;
  }
}
