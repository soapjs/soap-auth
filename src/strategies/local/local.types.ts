import { CredentialBasedAuthStrategyConfig } from "../../types";

export interface LocalStrategyConfig<TContext = unknown, TUser = unknown>
  extends CredentialBasedAuthStrategyConfig<TContext, TUser> {}
