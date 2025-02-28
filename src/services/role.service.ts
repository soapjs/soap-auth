import * as Soap from "@soapjs/soap";
import { RoleAuthorizationConfig } from "../types";
import { UnauthorizedRoleError } from "../errors";

export class RoleService<TUser> {
  private roles: string[];
  constructor(
    private config: RoleAuthorizationConfig,
    private logger: Soap.Logger
  ) {
    this.roles = config.roles || [];
  }

  public async isAuthorized(user: TUser): Promise<boolean> {
    if (
      typeof this.config.authorizeByRoles === "function" &&
      Array.isArray(this.roles) &&
      this.roles.length > 0
    ) {
      const hasAccess = await this.config.authorizeByRoles(user, this.roles);

      if (!hasAccess) {
        throw new UnauthorizedRoleError();
      }
    }

    return true;
  }
}
