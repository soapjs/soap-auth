import * as Soap from "@soapjs/soap";
import { SessionConfig } from "../session";
import { TokenConfig } from "../jwt";

/**
 * Configuration for API Key Strategy
 * @typedef {Object} ApiKeyStrategyConfig
 * @property {string} [headerName] - Name of the header containing the API key.
 * @property {string} [queryParamName] - Name of the query parameter containing the API key.
 * @property {string} [bodyParamName] - Name of the body parameter containing the API key.
 * @property {function} validate - Function to validate the API key.
 * @property {SessionConfig} [session] - Session configuration.
 * @property {TokenConfig} [jwt] - JWT configuration for this strategy.
 */
export interface ApiKeyStrategyConfig {
  headerName?: string;
  queryParamName?: string;
  bodyParamName?: string;
  validate: (apiKey: string) => Promise<any>;
  session?: SessionConfig;
  jwt?: TokenConfig;
}
