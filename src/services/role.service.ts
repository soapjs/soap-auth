import * as Soap from "@soapjs/soap";
import { RoleAuthorizationConfig } from "../types";
import { UnauthorizedRoleError } from "../errors";

export class RoleService<TUser> {
  constructor(
    private config: RoleAuthorizationConfig,
    private logger: Soap.Logger
  ) {}

  public async isAuthorized(user: TUser): Promise<boolean> {
    if (
      typeof this.config.authorizeByRoles === "function" &&
      Array.isArray(this.config?.roles) &&
      this.config.roles.length > 0
    ) {
      const hasAccess = await this.config.authorizeByRoles(
        user,
        this.config.roles
      );

      if (!hasAccess) {
        throw new UnauthorizedRoleError();
      }
    }

    return true;
  }
}
