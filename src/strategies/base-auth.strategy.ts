import * as Soap from "@soapjs/soap";
import {
  AuthFailureContext,
  AuthResult,
  AuthStrategy,
  AuthSuccessContext,
  BaseAuthStrategyConfig,
} from "../types";
import {
  AccountLockedError,
  RateLimitExceededError,
  UnauthorizedRoleError,
} from "../errors";
import { SessionHandler } from "../session/session-handler";

export abstract class BaseAuthStrategy<TContext = unknown, TUser = unknown>
  implements AuthStrategy<TContext, TUser>
{
  /**
   * Abstract method to authenticate user, must be implemented by concrete strategies.
   */
  abstract authenticate(context?: TContext): Promise<AuthResult<TUser>>;

  /**
   * Handles the logout process by revoking tokens and clearing sessions.
   * @param context - The request context.
   */
  abstract logout(context: TContext): Promise<void>;

  constructor(
    protected config: BaseAuthStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {}

  /**
   * Initializes the strategy (optional override).
   * For most strategies, this can be a no-op.
   */
  async init(): Promise<void> {
    return Promise.resolve();
  }

  /**
   * Checks if the user's account is locked.
   * Can be overridden by specific strategies or provided via config.
   */
  protected async isAccountLocked(account: any): Promise<boolean> {
    if (await this.config.lock.isAccountLocked?.(account)) {
      throw new AccountLockedError();
    }

    return false;
  }

  protected async isAuthorized(user: TUser): Promise<boolean> {
    if (this.config.role.authorizeByRoles && this.config.role.roles) {
      const hasAccess = await this.config.role.authorizeByRoles(
        user,
        this.config.role.roles
      );
      if (!hasAccess) {
        throw new UnauthorizedRoleError();
      }
    }

    return true;
  }

  /**
   * Checks if the rate limit has been exceeded.
   * Can be overridden by specific strategies or provided via config.
   */
  protected async checkRateLimit(data: unknown): Promise<void> {
    if (
      this.config.rateLimit.checkRateLimit &&
      (await this.config.rateLimit.checkRateLimit(data))
    ) {
      throw new RateLimitExceededError();
    }
  }

  protected async checkMfa(user: TUser, context: TContext): Promise<void> {
    try {
      if (this.config.mfa?.isMfaRequired?.(user)) {
        const mfaCode = this.config.mfa?.extractMfaCode?.(context);

        if (!mfaCode) {
          await this.config.mfa.sendMfaCode?.(user, context);
          throw new Error("2FA required. A verification code has been sent.");
        }

        const attempts = (await this.config.mfa.getMfaAttempts?.(user)) || 0;
        if (
          this.config.mfa.maxMfaAttempts &&
          attempts >= this.config.mfa.maxMfaAttempts
        ) {
          this.logger?.warn(`User ${user} exceeded maximum MFA attempts.`);
          await this.config.mfa.lockMfaOnFailure?.(user);
          throw new Error(
            "Your account has been temporarily locked due to too many failed 2FA attempts."
          );
        }

        const isValidMfa = await this.config.mfa.validateMfaCode?.(
          user,
          mfaCode
        );
        if (!isValidMfa) {
          this.logger?.warn(`Invalid MFA code attempt for user: ${user}`);
          await this.config.mfa.incrementMfaAttempts?.(user);
          throw new Error("Invalid 2FA code provided.");
        }

        await this.config.mfa.resetMfaAttempts?.(user);

        this.logger?.info(`2FA successfully validated for user: ${user}`);
      }
    } catch (error) {
      this.logger?.error(`2FA validation error for user: ${user}`, error);
      throw error;
    }
  }

  protected async onSuccess(
    action: string,
    context: AuthSuccessContext<TUser, TContext>
  ) {
    try {
      await this.config.onSuccess?.(action, context);
    } catch (error) {
      this.logger?.error(error);
    }
  }

  protected async onFailure(
    action: string,
    context: AuthFailureContext<TContext>
  ) {
    try {
      await this.config.onFailure?.(action, context);
    } catch (error) {
      this.logger?.error(error);
    }
  }
}
