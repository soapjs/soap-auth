import * as Soap from "@soapjs/soap";
import {
  AuthFailureContext,
  AuthResult,
  AuthStrategy,
  AuthSuccessContext,
  BaseAuthStrategyConfig,
} from "../types";
import { SessionHandler } from "../session/session-handler";
import {
  InvalidSessionError,
  MissingSessionIdError,
} from "../session/session.errors";
import { AccountLockService } from "../services/account-lock.service";
import { MfaService } from "../services/mfa.service";
import { RateLimitService } from "../services/rate-limit.service";
import { RoleService } from "../services/role.service";
import { AuthThrottleService } from "../services/auth-throttle.service";

export abstract class BaseAuthStrategy<TContext = unknown, TUser = unknown>
  implements AuthStrategy<TContext, TUser>
{
  protected accountLock: AccountLockService<TContext>;
  protected mfa: MfaService<TContext, TUser>;
  protected rateLimit: RateLimitService;
  protected role: RoleService<TUser>;
  protected throttle: AuthThrottleService;

  /**
   * Abstract method to authenticate user, must be implemented by concrete strategies.
   */
  abstract authenticate(context?: TContext): Promise<AuthResult<TUser>>;

  constructor(
    protected config: BaseAuthStrategyConfig<TContext, TUser>,
    protected session?: SessionHandler,
    protected logger?: Soap.Logger
  ) {
    if (config.mfa) {
      this.mfa = new MfaService(config.mfa, logger);
    }
    if (config.lock) {
      this.accountLock = new AccountLockService(config.lock, logger);
    }
    if (config.rateLimit) {
      this.rateLimit = new RateLimitService(config.rateLimit, logger);
    }
    if (config.role) {
      this.role = new RoleService(config.role, logger);
    }
    if (config.throttle) {
      this.throttle = new AuthThrottleService(config.throttle, logger);
    }
  }

  /**
   * Initializes the strategy (optional override).
   * For most strategies, this can be a no-op.
   */
  async init(): Promise<void> {
    return Promise.resolve();
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
    this.logger?.error(`${action} failed:`, context.error);
    try {
      await this.config.onFailure?.(action, context);
    } catch (e) {
      this.logger?.error(e);
    }
  }

  protected async authenticateWithSession(
    context: TContext
  ): Promise<AuthResult<TUser>> {
    if (this.rateLimit) {
      await this.rateLimit.checkRateLimit(context);
    }
    if (this.session) {
      let sessionId = this.session.getSessionId(context);

      if (!sessionId) throw new MissingSessionIdError();

      const sessionData = await this.session.getSessionData(sessionId);
      if (!sessionData) throw new InvalidSessionError();

      const user: TUser = sessionData.user;

      if (this.role) {
        await this.role.isAuthorized(user);
      }

      return { user };
    }
  }
}
