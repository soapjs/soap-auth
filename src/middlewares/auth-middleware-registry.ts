import * as Soap from "@soapjs/soap";
import { AuthenticatedOnlyMiddleware } from "./authenticated-only.middleware";

export class AuthMiddlewareRegistry extends Soap.AuthMiddlewareRegistry {
  getAuthenticatedOnlyMiddleware(): Soap.Middleware {
    return this.middlewares.get(Soap.MiddlewareType.AuthenticatedOnly);
  }

  setAuthenticatedOnlyMiddleware(strategy: string, session?: boolean) {
    this.middlewares.set(
      Soap.MiddlewareType.AuthenticatedOnly,
      new AuthenticatedOnlyMiddleware(strategy, session)
    );
  }
}
