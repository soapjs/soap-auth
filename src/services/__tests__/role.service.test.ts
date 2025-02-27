import { UnauthorizedRoleError } from "../../errors";
import { RoleService } from "../role.service";

const mockConfig = {
  authorizeByRoles: jest.fn(),
  roles: ["admin", "editor"],
};

const mockLogger = {
  error: jest.fn(),
};

describe("RoleService", () => {
  let service;
  const mockUser = { id: "user123", role: "viewer" };

  beforeEach(() => {
    jest.clearAllMocks();
    service = new RoleService(mockConfig, mockLogger as any);
  });

  it("isAuthorized throws UnauthorizedRoleError if user is not authorized", async () => {
    mockConfig.authorizeByRoles.mockResolvedValue(false);
    await expect(service.isAuthorized(mockUser)).rejects.toThrow(
      UnauthorizedRoleError
    );
  });

  it("isAuthorized returns true if user is authorized", async () => {
    mockConfig.authorizeByRoles.mockResolvedValue(true);
    await expect(service.isAuthorized(mockUser)).resolves.toBe(true);
  });

  it("isAuthorized bypasses role check if authorizeByRoles is not defined", async () => {
    service = new RoleService({ roles: [] }, mockLogger as any);
    await expect(service.isAuthorized(mockUser)).resolves.toBe(true);
  });
});
