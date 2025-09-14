import { ValidationUtils, ValidationError } from "../validation";

describe("ValidationUtils", () => {
  describe("required", () => {
    it("should not throw for valid values", () => {
      expect(() => ValidationUtils.required("test", "field")).not.toThrow();
      expect(() => ValidationUtils.required(0, "field")).not.toThrow();
      expect(() => ValidationUtils.required(false, "field")).not.toThrow();
      expect(() => ValidationUtils.required([], "field")).not.toThrow();
      expect(() => ValidationUtils.required({}, "field")).not.toThrow();
    });

    it("should throw ValidationError for null or undefined", () => {
      expect(() => ValidationUtils.required(null, "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.required(undefined, "field")).toThrow(ValidationError);
    });

    it("should include field name in error message", () => {
      expect(() => ValidationUtils.required(null, "testField")).toThrow("testField is required");
    });
  });

  describe("nonEmptyString", () => {
    it("should return trimmed string for valid input", () => {
      expect(ValidationUtils.nonEmptyString("  test  ", "field")).toBe("test");
    });

    it("should throw for non-string input", () => {
      expect(() => ValidationUtils.nonEmptyString(123, "field")).toThrow(ValidationError);
    });

    it("should throw for empty string", () => {
      expect(() => ValidationUtils.nonEmptyString("", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.nonEmptyString("   ", "field")).toThrow(ValidationError);
    });

    it("should throw for null or undefined", () => {
      expect(() => ValidationUtils.nonEmptyString(null, "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.nonEmptyString(undefined, "field")).toThrow(ValidationError);
    });
  });

  describe("email", () => {
    it("should return email for valid input", () => {
      expect(ValidationUtils.email("test@example.com", "field")).toBe("test@example.com");
    });

    it("should throw for invalid email format", () => {
      expect(() => ValidationUtils.email("invalid-email", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.email("@example.com", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.email("test@", "field")).toThrow(ValidationError);
    });
  });

  describe("password", () => {
    it("should return password for valid input", () => {
      expect(ValidationUtils.password("password123", "field")).toBe("password123");
    });

    it("should throw for short password", () => {
      expect(() => ValidationUtils.password("short", "field", 8)).toThrow(ValidationError);
    });

    it("should use default minimum length", () => {
      expect(() => ValidationUtils.password("short", "field")).toThrow(ValidationError);
    });
  });

  describe("positiveNumber", () => {
    it("should return number for valid input", () => {
      expect(ValidationUtils.positiveNumber(5, "field")).toBe(5);
      expect(ValidationUtils.positiveNumber("10", "field")).toBe(10);
    });

    it("should throw for non-positive numbers", () => {
      expect(() => ValidationUtils.positiveNumber(0, "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.positiveNumber(-1, "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.positiveNumber("abc", "field")).toThrow(ValidationError);
    });
  });

  describe("range", () => {
    it("should return number within range", () => {
      expect(ValidationUtils.range(5, "field", 1, 10)).toBe(5);
    });

    it("should throw for numbers outside range", () => {
      expect(() => ValidationUtils.range(0, "field", 1, 10)).toThrow(ValidationError);
      expect(() => ValidationUtils.range(11, "field", 1, 10)).toThrow(ValidationError);
    });
  });

  describe("oneOf", () => {
    it("should return value if it's in allowed values", () => {
      expect(ValidationUtils.oneOf("test", "field", ["test", "other"])).toBe("test");
    });

    it("should throw if value is not in allowed values", () => {
      expect(() => ValidationUtils.oneOf("invalid", "field", ["test", "other"])).toThrow(ValidationError);
    });
  });

  describe("url", () => {
    it("should return URL for valid input", () => {
      expect(ValidationUtils.url("https://example.com", "field")).toBe("https://example.com");
    });

    it("should throw for invalid URL", () => {
      expect(() => ValidationUtils.url("not-a-url", "field")).toThrow(ValidationError);
    });
  });

  describe("jwtToken", () => {
    it("should return token for valid JWT format", () => {
      const token = "header.payload.signature";
      expect(ValidationUtils.jwtToken(token, "field")).toBe(token);
    });

    it("should throw for invalid JWT format", () => {
      expect(() => ValidationUtils.jwtToken("invalid", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.jwtToken("header.payload", "field")).toThrow(ValidationError);
    });
  });

  describe("uuid", () => {
    it("should return UUID for valid input", () => {
      const uuid = "123e4567-e89b-12d3-a456-426614174000";
      expect(ValidationUtils.uuid(uuid, "field")).toBe(uuid);
    });

    it("should throw for invalid UUID", () => {
      expect(() => ValidationUtils.uuid("not-a-uuid", "field")).toThrow(ValidationError);
    });
  });

  describe("object", () => {
    it("should return object for valid input", () => {
      const obj = { test: "value" };
      expect(ValidationUtils.object(obj, "field")).toBe(obj);
    });

    it("should throw for non-object input", () => {
      expect(() => ValidationUtils.object("string", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.object([], "field")).toThrow(ValidationError);
    });
  });

  describe("array", () => {
    it("should return array for valid input", () => {
      const arr = [1, 2, 3];
      expect(ValidationUtils.array(arr, "field")).toBe(arr);
    });

    it("should throw for non-array input", () => {
      expect(() => ValidationUtils.array("string", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.array({}, "field")).toThrow(ValidationError);
    });
  });

  describe("function", () => {
    it("should return function for valid input", () => {
      const fn = () => {};
      expect(ValidationUtils.function(fn, "field")).toBe(fn);
    });

    it("should throw for non-function input", () => {
      expect(() => ValidationUtils.function("string", "field")).toThrow(ValidationError);
    });
  });

  describe("validateConfig", () => {
    it("should not throw for valid config", () => {
      const config = { field1: "value1", field2: "value2" };
      expect(() => ValidationUtils.validateConfig(config, ["field1", "field2"])).not.toThrow();
    });

    it("should throw for missing required fields", () => {
      const config = { field1: "value1" };
      expect(() => ValidationUtils.validateConfig(config, ["field1", "field2"])).toThrow(ValidationError);
    });
  });

  describe("pattern", () => {
    it("should return string for matching pattern", () => {
      const regex = /^[a-z]+$/;
      expect(ValidationUtils.pattern("test", "field", regex)).toBe("test");
    });

    it("should throw for non-matching pattern", () => {
      const regex = /^[a-z]+$/;
      expect(() => ValidationUtils.pattern("TEST", "field", regex)).toThrow(ValidationError);
    });
  });

  describe("date", () => {
    it("should return Date for valid input", () => {
      const date = ValidationUtils.date("2023-01-01", "field");
      expect(date).toBeInstanceOf(Date);
    });

    it("should throw for invalid date", () => {
      expect(() => ValidationUtils.date("invalid-date", "field")).toThrow(ValidationError);
    });
  });

  describe("boolean", () => {
    it("should return boolean for valid input", () => {
      expect(ValidationUtils.boolean(true, "field")).toBe(true);
      expect(ValidationUtils.boolean(false, "field")).toBe(false);
    });

    it("should throw for non-boolean input", () => {
      expect(() => ValidationUtils.boolean("true", "field")).toThrow(ValidationError);
      expect(() => ValidationUtils.boolean(1, "field")).toThrow(ValidationError);
    });
  });
});
