import { CredentialAuthStrategyConfig } from "../../types";

export interface BasicStrategyConfig<TContext = unknown, TUser = unknown>
  extends CredentialAuthStrategyConfig<TContext, TUser> {}

export type BasicContext = {
  headers: { authorization: string; [key: string]: string };
  [key: string]: unknown;
};
