# LDAP Examples (WIP)**

```typescript
import ldap from "ldapjs";
import * as Soap from "@soapjs/soap";
import { CredentialBasedAuthStrategy } from "./credential-based-auth.strategy";
import { TokenConfig } from "../tokens/types";
import { CredentialBasedAuthStrategyConfig, TokenHandlersConfig } from "../types";
import { SessionConfig } from "../session/session.types";
import {
  AuthError,
  InvalidCredentialsError,
  MissingCredentialsError,
  MissingUserDataError,
} from "../errors";

/**
 * Interface defining the LDAP configuration options.
 */
export interface LdapStrategyConfig<TContext = unknown, TUser = unknown>
  extends CredentialBasedAuthStrategyConfig<TContext, TUser> {
  ldapUrl: string;
  baseDn: string;
  bindDn: string;
  bindCredentials: string;
  userFilter: string;
  groupFilter?: string;
  mapUserAttributes?: (ldapEntry: any) => TUser;
}

/**
 * LDAP authentication strategy.
 *
 * @template TContext - The type of the authentication context.
 * @template TUser - The type of the authenticated user.
 */
export class LdapStrategy<
  TContext = unknown,
  TUser = unknown
> extends CredentialBasedAuthStrategy<TContext, TUser> {
  constructor(
    protected config: LdapStrategyConfig<TContext, TUser>,
    protected tokenHandlers?: TokenHandlersConfig,
    protected session?: SessionConfig,
    protected logger?: Soap.Logger
  ) {
    super(config, tokenHandlers, session, logger);
  }

  /**
   * Extracts credentials (username and password) from the provided context.
   * @param context - The authentication context.
   * @returns {Promise<{ identifier: string; password: string }>} Extracted credentials.
   */
  protected async extractCredentials(
    context?: TContext
  ): Promise<{ identifier: string; password: string }> {
    const { identifier, password } = context as any;

    if (!identifier || !password) {
      throw new MissingCredentialsError();
    }

    return { identifier, password };
  }

  /**
   * Verifies if the provided credentials are correct by binding to the LDAP server.
   * @param credentials - The extracted credentials.
   * @returns {Promise<boolean>} True if credentials are valid.
   */
  protected async verifyCredentials(credentials: {
    identifier: string;
    password: string;
  }): Promise<boolean> {
    const client = ldap.createClient({ url: this.config.ldapUrl });

    return new Promise((resolve, reject) => {
      const userDn = `uid=${credentials.identifier},${this.config.baseDn}`;
      client.bind(userDn, credentials.password, (err) => {
        if (err) {
          this.logger?.warn(
            `LDAP authentication failed for ${credentials.identifier}`
          );
          reject(new InvalidCredentialsError());
        } else {
          this.logger?.info(
            `LDAP authentication successful for ${credentials.identifier}`
          );
          resolve(true);
        }
        client.unbind();
      });
    });
  }

  /**
   * Retrieves user data from the LDAP directory.
   * @param credentials - The extracted credentials.
   * @returns {Promise<TUser | null>} Retrieved user data.
   */
  protected async retrieveUser(credentials: {
    identifier: string;
    password: string;
  }): Promise<TUser | null> {
    const client = ldap.createClient({ url: this.config.ldapUrl });

    return new Promise<TUser | null>((resolve, reject) => {
      client.bind(this.config.bindDn, this.config.bindCredentials, (err) => {
        if (err) {
          this.logger?.error("Failed to bind as admin to retrieve user data.");
          reject(new AuthError(err, "LDAP admin bind failed."));
          return;
        }

        const searchOptions = {
          filter: this.config.userFilter.replace(
            "{{identifier}}",
            credentials.identifier
          ),
          scope: "sub",
        };

        client.search(this.config.baseDn, searchOptions, (err, res) => {
          if (err) {
            reject(new MissingUserDataError());
            return;
          }

          let userEntry: TUser | null = null;
          res.on("searchEntry", (entry) => {
            userEntry = this.config.mapUserAttributes
              ? this.config.mapUserAttributes(entry.object)
              : (entry.object as TUser);
          });

          res.on("end", () => {
            client.unbind();
            if (userEntry) {
              resolve(userEntry);
            } else {
              reject(new MissingUserDataError());
            }
          });

          res.on("error", (err) => {
            client.unbind();
            reject(new AuthError(err, "LDAP search failed."));
          });
        });
      });
    });
  }

  /**
   * Checks if the user belongs to a required group.
   * @param user - The authenticated user object.
   * @returns {Promise<boolean>} True if user belongs to the required group.
   */
  protected async isAuthorized(user: TUser): Promise<boolean> {
    if (!this.config.groupFilter) return true;

    const client = ldap.createClient({ url: this.config.ldapUrl });

    return new Promise<boolean>((resolve, reject) => {
      client.bind(this.config.bindDn, this.config.bindCredentials, (err) => {
        if (err) {
          reject(new AuthError(err, "LDAP admin bind failed."));
          return;
        }

        const searchOptions = {
          filter: this.config.groupFilter!.replace(
            "{{identifier}}",
            (user as any).id
          ),
          scope: "sub",
        };

        client.search(this.config.baseDn, searchOptions, (err, res) => {
          if (err) {
            reject(new AuthError(err, "LDAP group search failed."));
            return;
          }

          let isAuthorized = false;
          res.on("searchEntry", () => {
            isAuthorized = true;
          });

          res.on("end", () => {
            client.unbind();
            resolve(isAuthorized);
          });

          res.on("error", (err) => {
            client.unbind();
            reject(new AuthError(err, "LDAP group membership check failed."));
          });
        });
      });
    });
  }

  /**
   * Logs out the user by invalidating the session.
   * @param context - The authentication context.
   */
  async logout(context?: TContext): Promise<void> {
    await super.logout(context);
  }

  /**
   * Tests the LDAP connection.
   * @returns {Promise<boolean>} True if connection is successful.
   */
  async checkLdapConnection(): Promise<boolean> {
    const client = ldap.createClient({ url: this.config.ldapUrl });

    return new Promise<boolean>((resolve, reject) => {
      client.bind(this.config.bindDn, this.config.bindCredentials, (err) => {
        if (err) {
          this.logger?.error("LDAP connection test failed.");
          reject(false);
        } else {
          this.logger?.info("LDAP connection test successful.");
          resolve(true);
        }
        client.unbind();
      });
    });
  }
}
```