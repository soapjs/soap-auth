import { jest } from "@jest/globals";
import { SoapAuth } from "../soap-auth";
import { AuthResult, AuthStrategy } from "../types";

describe("SoapAuth", () => {
  let soapAuth;
  const mockLogger: any = { error: jest.fn(), info: jest.fn() };
  const mockStrategy: any = {
    authenticate: jest.fn(),
    init: jest.fn(),
    logout: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    soapAuth = new SoapAuth({ logger: mockLogger });
  });

  test("addStrategy should add a valid strategy", () => {
    expect(() =>
      soapAuth.addStrategy(mockStrategy, "jwt", "http")
    ).not.toThrow();
    expect(soapAuth.hasStrategy("jwt", "http")).toBe(true);
  });

  test("addStrategy should throw error if strategy is invalid", () => {
    expect(() => soapAuth.addStrategy({}, "invalid", "http")).toThrow(
      "Invalid authentication strategy: does not implement required methods."
    );
  });

  test("removeStrategy should remove an existing strategy", () => {
    soapAuth.addStrategy(mockStrategy, "jwt", "http");
    expect(soapAuth.hasStrategy("jwt", "http")).toBe(true);
    soapAuth.removeStrategy("jwt", "http");
    expect(soapAuth.hasStrategy("jwt", "http")).toBe(false);
  });

  test("getStrategy should return an existing strategy", () => {
    soapAuth.addStrategy(mockStrategy, "jwt", "http");
    expect(soapAuth.getStrategy("jwt", "http")).toBe(mockStrategy);
  });

  test("getStrategy should throw an error if strategy does not exist", () => {
    expect(() => soapAuth.getStrategy("nonexistent", "http")).toThrow(
      'Authentication strategy "nonexistent" not found.'
    );
  });

  test("listStrategies should return all registered strategy names", () => {
    soapAuth.addStrategy(mockStrategy, "jwt", "http");
    soapAuth.addStrategy(mockStrategy, "oauth", "http");
    expect(soapAuth.listStrategies("http")).toEqual(["jwt", "oauth"]);
  });
});
