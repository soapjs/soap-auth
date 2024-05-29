import {
  ApiKeyStrategyConfig,
  AuthStrategy,
  BasicStrategyConfig,
  LocalStrategyConfig,
  OAuth2Config,
  TokenStrategyConfig,
  Web3StrategyConfig,
} from "../strategies";

export interface SoapAuthConfig {
  local?: LocalStrategyConfig;
  oauth2?: { [provider: string]: OAuth2Config };
  apiKey?: ApiKeyStrategyConfig;
  token?: TokenStrategyConfig;
  basic?: BasicStrategyConfig;
  web3?: Web3StrategyConfig;
  custom: { [provider: string]: AuthStrategy };
}
