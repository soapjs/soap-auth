import { CredentialBasedAuthStrategyConfig } from "../../types";

export interface BasicStrategyConfig<TContext = unknown, TUser = unknown>
  extends CredentialBasedAuthStrategyConfig<TContext, TUser> {}

export type BasicContext = {
  headers: { authorization: string; [key: string]: string };
  [key: string]: unknown;
};
