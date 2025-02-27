import * as Soap from "@soapjs/soap";
import { RateLimitConfig } from "../types";
import { RateLimitExceededError } from "../errors";

export class RateLimitService {
  constructor(private config: RateLimitConfig, private logger: Soap.Logger) {}

  public async incrementRequestCount(...args: unknown[]) {
    try {
      await this.config.incrementRequestCount(...args);
    } catch (error) {
      this.logger?.error(error);
    }
  }

  public async checkRateLimit(data: unknown): Promise<void> {
    if (await this.config.checkRateLimit?.(data)) {
      throw new RateLimitExceededError();
    }
  }
}
