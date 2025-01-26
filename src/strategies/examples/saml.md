# SAML Examples (WIP)**

```typescript
import * as Soap from "@soapjs/soap";
import * as saml from "samlify";
import * as fs from "fs";
import { CredentialBasedAuthStrategy } from "./credential-based-auth.strategy";
import { CredentialBasedAuthStrategyConfig } from "../types";

type SAMLContext = { SAMLResponse: any; [key: string]: any };

export interface SAMLStrategyConfig<TContext = unknown, TUser = unknown>
  extends CredentialBasedAuthStrategyConfig<TContext, TUser> {
  idpMetadataFile: string;
  spEntityId: string;
  callbackUrl: string;
  spPrivateKeyFile: string;
  spPrivateKeyPass: string;
  mapUserAttributes: (...args: unknown[]) => TUser;
}

export class SAMLStrategy<
  TContext extends SAMLContext = SAMLContext,
  TUser = unknown
> extends CredentialBasedAuthStrategy<TContext, TUser> {
  private serviceProvider: saml.ServiceProviderInstance;
  private identityProvider: saml.IdentityProviderInstance;

  constructor(protected config: SAMLStrategyConfig<TContext, TUser>) {
    super(config);

    this.identityProvider = saml.IdentityProvider({
      metadata: fs.readFileSync(config.idpMetadataFile, "utf-8"),
      isAssertionEncrypted: false,
      wantLogoutResponseSigned: true,
      wantAuthnRequestsSigned: true,
    });

    this.serviceProvider = saml.ServiceProvider({
      entityID: config.spEntityId,
      assertionConsumerService: [
        {
          Binding: saml.Constants.namespace.post,
          Location: config.callbackUrl,
        },
      ],
      privateKey: fs.readFileSync(config.spPrivateKeyFile, "utf-8"),
      privateKeyPass: config.spPrivateKeyPass || "",
    });
  }

  /**
   * Generates an authentication URL to redirect users to Google Workspace SSO.
   * @returns {Promise<string>} The SSO login URL.
   */
  async generateLoginRequestUrl(): Promise<string> {
    const { context } = await this.serviceProvider.createLoginRequest(
      this.identityProvider,
      "redirect"
    );
    return context; // Redirect URL to IdP (Google SSO)
  }

  /**
   * Handles the SAML authentication response from Google.
   * @param {TContext} context - The request context with SAMLResponse.
   * @returns {Promise<TUser>} Authenticated user data.
   */
  protected async extractCredentials(context?: TContext): Promise<any> {
    if (!context?.SAMLResponse) {
      throw new Error("Missing SAMLResponse");
    }

    try {
      const { extract } = await this.serviceProvider.parseLoginResponse(
        this.identityProvider,
        "post",
        context
      );
      return extract;
    } catch (error) {
      throw new Error("Invalid SAMLResponse");
    }
  }

  /**
   * Verifies if the provided SAML assertion is valid.
   * @param credentials - The SAML response.
   * @returns {Promise<boolean>} True if assertion is valid.
   */
  protected async verifyCredentials(credentials: any): Promise<boolean> {
    return credentials && credentials.extract && credentials.extract.nameID
      ? true
      : false;
  }

  /**
   * Maps the SAML assertion attributes to the user object.
   * @param credentials - The SAML response.
   * @returns {Promise<TUser | null>} The user object.
   */
  protected async retrieveUser(credentials: any): Promise<TUser | null> {
    return this.config.mapUserAttributes(credentials.extract.attributes);
  }
}
```