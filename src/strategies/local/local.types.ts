import { CredentialAuthStrategyConfig } from "../../types";

export interface LocalStrategyConfig<TContext = unknown, TUser = unknown>
  extends CredentialAuthStrategyConfig<TContext, TUser> {}
