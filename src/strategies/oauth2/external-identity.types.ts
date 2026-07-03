import * as Soap from "@soapjs/soap";

export type ExternalIdentity = {
  provider: string;
  providerUserId: string;
  email?: string;
  emailVerified?: boolean;
  username?: string;
  name?: string;
  picture?: string;
  raw?: unknown;
};

export interface ExternalIdentityConfig<
  TContext = Soap.HttpContext,
  TUser extends Soap.AuthUser = Soap.AuthUser
> {
  resolveIdentity: (
    identity: ExternalIdentity,
    context: TContext
  ) => Promise<TUser | null>;
  mapProfile?: (
    profile: unknown,
    provider: string,
    context: TContext
  ) => ExternalIdentity | Promise<ExternalIdentity>;
}
