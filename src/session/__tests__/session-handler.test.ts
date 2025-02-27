import * as Soap from "@soapjs/soap";
import { SessionHandler } from "../session-handler";
import { MissingSessionIdError } from "../session.errors";

interface MockSessionData {
  user?: {
    id?: string;
    name?: string;
  };
  createdAt?: number;
}

describe("SessionHandler", () => {
  let mockStore: any;
  let mockLogger: Partial<Soap.Logger>;
  let sessionHandler: SessionHandler<any, any, MockSessionData>;
  let config: any;

  beforeEach(() => {
    mockStore = {
      getSession: jest.fn(),
      setSession: jest.fn(),
      touchSession: jest.fn(),
      destroySession: jest.fn(),
      getSessionIds: jest.fn().mockResolvedValue(["s1", "s2"]),
    };

    mockLogger = {
      info: jest.fn(),
      error: jest.fn(),
      warn: jest.fn(),
    };

    config = {
      store: mockStore,
      sessionKey: "CUSTOMSESSION",
      sessionHeader: "x-custom-session",
      logger: mockLogger,
      cookie: {
        maxAge: 3600,
      },
      generateSessionId: jest.fn(),
      getSessionId: undefined,
      embedSessionId: undefined,
      createSessionData: undefined,
    };

    sessionHandler = new SessionHandler(config, mockLogger as Soap.Logger);
  });

  // ------------------------------------------------------------------------------
  // Constructor
  // ------------------------------------------------------------------------------
  describe("constructor", () => {
    it("should throw if store is not provided", () => {
      expect(() => {
        new SessionHandler({} as any);
      }).toThrowError("Session store is required.");
    });

    it("should set default sessionKey and headerKey if not provided", () => {
      const newHandler = new SessionHandler({ store: mockStore } as any);
      expect((newHandler as any).sessionKey).toBe("SESSIONID");
      expect((newHandler as any).headerKey).toBe("x-session-id");
    });

    it("should use provided sessionKey and headerKey if available", () => {
      expect((sessionHandler as any).sessionKey).toBe("CUSTOMSESSION");
      expect((sessionHandler as any).headerKey).toBe("x-custom-session");
    });
  });

  // ------------------------------------------------------------------------------
  // setSessionId
  // ------------------------------------------------------------------------------
  describe("setSessionId", () => {
    it("should call config.embedSessionId if defined", () => {
      config.embedSessionId = jest.fn();
      const handler = new SessionHandler(config, mockLogger as Soap.Logger);

      const context: any = {};
      handler.setSessionId(context, "session123");

      expect(config.embedSessionId).toHaveBeenCalledWith(context, "session123");
    });

    it("should set session ID in cookie if res.cookie is available", () => {
      const context: any = {
        res: {
          cookie: jest.fn(),
        },
      };
      sessionHandler.setSessionId(context, "sessionABC");

      expect(context.res.cookie).toHaveBeenCalledWith(
        "CUSTOMSESSION",
        "sessionABC",
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: "strict",
        })
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        `Session ID set in cookie: CUSTOMSESSION`
      );
    });

    it("should set session ID in header if res.setHeader is available", () => {
      const context: any = {
        res: {
          setHeader: jest.fn(),
        },
      };
      sessionHandler.setSessionId(context, "headerSessionId");
      expect(context.res.setHeader).toHaveBeenCalledWith(
        "x-custom-session",
        "headerSessionId"
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        `Session ID set in header: x-custom-session`
      );
    });

    it("should set sessionId directly on context object if no res", () => {
      const context: any = {};
      sessionHandler.setSessionId(context, "direct123");
      expect(context.sessionId).toBe("direct123");
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Session ID set in context object"
      );
    });

    it("should log error if something goes wrong", () => {
      config.embedSessionId = jest.fn().mockImplementation(() => {
        throw new Error("Test error");
      });
      const handler = new SessionHandler(config, mockLogger as Soap.Logger);

      handler.setSessionId({}, "boom");
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error setting session ID:",
        expect.any(Error)
      );
    });
  });

  // ------------------------------------------------------------------------------
  // getSessionId
  // ------------------------------------------------------------------------------
  describe("getSessionId", () => {
    it("should use config.getSessionId if defined", () => {
      config.getSessionId = jest.fn().mockReturnValue("customSessionId");
      const handler = new SessionHandler(config, mockLogger as Soap.Logger);

      const sid = handler.getSessionId({});
      expect(sid).toBe("customSessionId");
      expect(config.getSessionId).toHaveBeenCalled();
    });

    it("should return cookie session if present", () => {
      const context: any = { cookies: { CUSTOMSESSION: "cookieValue" } };
      const sid = sessionHandler.getSessionId(context);
      expect(sid).toBe("cookieValue");
    });

    it("should return header session if present", () => {
      const context: any = { headers: { "x-custom-session": "headerValue" } };
      const sid = sessionHandler.getSessionId(context);
      expect(sid).toBe("headerValue");
    });

    it("should return sessionId if set directly on context", () => {
      const context: any = { sessionId: "directValue" };
      const sid = sessionHandler.getSessionId(context);
      expect(sid).toBe("directValue");
    });

    it("should return null if not found", () => {
      const context: any = {};
      const sid = sessionHandler.getSessionId(context);
      expect(sid).toBeNull();
    });

    it("should log error and return null if something goes wrong", () => {
      config.getSessionId = jest.fn().mockImplementation(() => {
        throw new Error("Get error");
      });
      const handler = new SessionHandler(config, mockLogger as Soap.Logger);
      const sid = handler.getSessionId({});
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error retrieving session ID:",
        expect.any(Error)
      );
      expect(sid).toBeNull();
    });
  });

  // ------------------------------------------------------------------------------
  // generateSessionId
  // ------------------------------------------------------------------------------
  describe("generateSessionId", () => {
    it("should use config.generateSessionId if provided", () => {
      config.generateSessionId.mockReturnValue("customGenerated");
      const sid = sessionHandler.generateSessionId();
      expect(sid).toBe("customGenerated");
      expect(config.generateSessionId).toHaveBeenCalled();
    });

    it("should fallback to uuid if no config.generateSessionId is given", () => {
      config.generateSessionId = undefined;
      const sid = sessionHandler.generateSessionId();
      expect(typeof sid).toBe("string");
      expect(sid.length).toBeGreaterThan(0);
    });
  });

  // ------------------------------------------------------------------------------
  // buildSessionData
  // ------------------------------------------------------------------------------
  describe("buildSessionData", () => {
    it("should call config.createSessionData if provided", () => {
      config.createSessionData = jest
        .fn()
        .mockReturnValue({ user: "mockUser" });
      const data = sessionHandler.buildSessionData({ id: "test" }, {});
      expect(config.createSessionData).toHaveBeenCalledWith({ id: "test" }, {});
      expect(data).toEqual({ user: "mockUser" });
    });

    it("should default to { user: data } if createSessionData not provided", () => {
      config.createSessionData = undefined;
      const input = { id: "testId" };
      const data = sessionHandler.buildSessionData(input);
      expect(data).toEqual({ user: input });
    });
  });

  // ------------------------------------------------------------------------------
  // getSessionData
  // ------------------------------------------------------------------------------
  describe("getSessionData", () => {
    it("should return data from the store", async () => {
      mockStore.getSession.mockResolvedValue({ user: { id: "1" } });
      const data = await sessionHandler.getSessionData("session123");
      expect(data).toEqual({ user: { id: "1" } });
    });

    it("should return null if store.getSession fails", async () => {
      mockStore.getSession.mockRejectedValue(new Error("Store error"));
      const data = await sessionHandler.getSessionData("sessionX");
      expect(data).toBeNull();
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error retrieving session data:",
        expect.any(Error)
      );
    });
  });

  // ------------------------------------------------------------------------------
  // setSessionData
  // ------------------------------------------------------------------------------
  describe("setSessionData", () => {
    it("should warn if sessionId is falsy", async () => {
      await sessionHandler.setSessionData("", { user: {} });
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "No session ID found, unable to set session."
      );
      expect(mockStore.setSession).not.toHaveBeenCalled();
    });

    it("should call store.setSession with provided data", async () => {
      await sessionHandler.setSessionData("sessionXYZ", {
        user: { id: "abc" },
      });
      expect(mockStore.setSession).toHaveBeenCalledWith("sessionXYZ", {
        user: { id: "abc" },
      });
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Session set for ID: sessionXYZ"
      );
    });

    it("should log error if store.setSession fails", async () => {
      mockStore.setSession.mockRejectedValue(new Error("Store error"));
      await sessionHandler.setSessionData("session123", {
        user: { id: "xyz" },
      });
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error storing session data:",
        expect.any(Error)
      );
    });
  });

  // ------------------------------------------------------------------------------
  // touch
  // ------------------------------------------------------------------------------
  describe("touch", () => {
    it("should warn if no sessionId is provided", async () => {
      await sessionHandler.touch("");
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "No session ID found, unable to touch session."
      );
    });

    it("should warn if session not found", async () => {
      mockStore.getSession.mockResolvedValue(null);
      await sessionHandler.touch("noSuchId", { user: { id: "1" } });
      expect(mockLogger.warn).toHaveBeenCalledWith(
        "Session not found for ID: noSuchId"
      );
    });

    it("should merge data and call store.touchSession if session found", async () => {
      mockStore.getSession.mockResolvedValue({ user: { id: "old" } });
      await sessionHandler.touch("session123", { user: { id: "new" } });
      expect(mockStore.touchSession).toHaveBeenCalledWith("session123", {
        user: { id: "new" },
      });
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Session touched for ID: session123"
      );
    });

    it("should log error on store errors", async () => {
      mockStore.getSession.mockResolvedValue({ user: {} });
      mockStore.touchSession.mockRejectedValue(new Error("Touch error"));
      await sessionHandler.touch("session123");
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error touching session:",
        expect.any(Error)
      );
    });
  });

  // ------------------------------------------------------------------------------
  // destroy
  // ------------------------------------------------------------------------------
  describe("destroy", () => {
    it("should call store.destroySession with sessionId", async () => {
      await sessionHandler.destroy("sessionABC");
      expect(mockStore.destroySession).toHaveBeenCalledWith("sessionABC");
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Session destroyed for ID: sessionABC"
      );
    });

    it("should do nothing if no sessionId is provided", async () => {
      await sessionHandler.destroy("");
      expect(mockStore.destroySession).not.toHaveBeenCalled();
    });

    it("should log error on store error", async () => {
      mockStore.destroySession.mockRejectedValue(new Error("Destroy error"));
      await sessionHandler.destroy("sessionXYZ");
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error destroying session:",
        expect.any(Error)
      );
    });
  });

  // ------------------------------------------------------------------------------
  // isSessionExpired
  // ------------------------------------------------------------------------------
  describe("isSessionExpired", () => {
    it("should return false if no sessionData or no createdAt", () => {
      expect(sessionHandler.isSessionExpired({} as any)).toBe(false);
      expect(sessionHandler.isSessionExpired(null as any)).toBe(false);
    });

    it("should return true if now - createdAt > maxAge", () => {
      const oldTime = Date.now() - 7200 * 1000; // 2 hours ago
      config.cookie.maxAge = 3600 * 1000; // 1 hour
      const data: MockSessionData = { createdAt: oldTime };
      expect(sessionHandler.isSessionExpired(data)).toBe(true);
    });

    it("should return false if within maxAge", () => {
      const recentTime = Date.now() - 1000 * 100; // 100 seconds ago
      config.cookie.maxAge = 600000; // 600k ms => 600s = 10 minutes
      const data: MockSessionData = { createdAt: recentTime };
      expect(sessionHandler.isSessionExpired(data)).toBe(false);
    });
  });

  // ------------------------------------------------------------------------------
  // issueSession
  // ------------------------------------------------------------------------------
  describe("issueSession", () => {
    it("should reuse existing sessionId if present in context", async () => {
      jest
        .spyOn(sessionHandler, "getSessionId")
        .mockReturnValue("ctxSessionId");

      await sessionHandler.issueSession({ id: "u1" }, {});
      expect(mockStore.setSession).toHaveBeenCalledWith("ctxSessionId", {
        user: { id: "u1" },
      });
    });

    it("should generate a new sessionId if none found in context", async () => {
      jest.spyOn(sessionHandler, "getSessionId").mockReturnValue(null);
      jest.spyOn(sessionHandler, "generateSessionId").mockReturnValue("newID");

      const result = await sessionHandler.issueSession({ id: "u1" }, {});
      expect(mockStore.setSession).toHaveBeenCalledWith("newID", {
        user: { id: "u1" },
      });
      expect(result.sessionId).toBe("newID");
    });

    it("should call session.createSessionData if provided in config", async () => {
      config.createSessionData = jest
        .fn()
        .mockReturnValue({ user: { id: "custom" }, extra: "hello" });
      config.embedSessionId = jest.fn();

      const handler = new SessionHandler(config, mockLogger as Soap.Logger);

      jest.spyOn(handler, "getSessionId").mockReturnValue("testSid");
      const result = await handler.issueSession({ id: "u2" }, {});

      expect(config.createSessionData).toHaveBeenCalledWith(
        { id: "u2" },
        {}
      );
      expect(mockStore.setSession).toHaveBeenCalledWith("testSid", {
        user: { id: "custom" },
        extra: "hello",
      });
      expect(result.data).toEqual({ user: { id: "custom" }, extra: "hello" });
    });

    it("should embed sessionId if embedSessionId is defined in config.session", async () => {
      config.embedSessionId = jest.fn();
      const handler = new SessionHandler(config, mockLogger as Soap.Logger);
      jest.spyOn(handler, "getSessionId").mockReturnValue("abc123");

      await handler.issueSession({ id: "u5" }, {});
      expect(config.embedSessionId).toHaveBeenCalledWith({}, "abc123");
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Stored user session with ID: abc123"
      );
    });
  });

  // ------------------------------------------------------------------------------
  // logoutSession
  // ------------------------------------------------------------------------------
  describe("logoutSession", () => {
    it("should throw MissingSessionIdError if sessionId not found", async () => {
      jest.spyOn(sessionHandler, "getSessionId").mockReturnValue(null);
      await expect(sessionHandler.logoutSession({})).rejects.toThrow(
        MissingSessionIdError
      );
    });

    it("should destroy session with found sessionId", async () => {
      jest
        .spyOn(sessionHandler, "getSessionId")
        .mockReturnValue("logoutSessionId");
      const destroySpy = jest.spyOn(sessionHandler, "destroy");

      await sessionHandler.logoutSession({});
      expect(destroySpy).toHaveBeenCalledWith("logoutSessionId");
      expect(mockLogger.info).toHaveBeenCalledWith(
        "Session destroyed: logoutSessionId"
      );
    });
  });

  // ------------------------------------------------------------------------------
  // clearAllSessions
  // ------------------------------------------------------------------------------
  describe("clearAllSessions", () => {
    it("should destroy all sessions if store.getSessionIds is available", async () => {
      mockStore.getSessionIds.mockResolvedValue(["s1", "s2", "s3"]);
      await sessionHandler.clearAllSessions();
      expect(mockStore.destroySession).toHaveBeenCalledWith("s1");
      expect(mockStore.destroySession).toHaveBeenCalledWith("s2");
      expect(mockStore.destroySession).toHaveBeenCalledWith("s3");
      expect(mockLogger.info).toHaveBeenCalledWith(
        "All sessions have been cleared."
      );
    });

    it("should log error if something goes wrong", async () => {
      mockStore.getSessionIds.mockRejectedValue(new Error("Store read error"));
      await sessionHandler.clearAllSessions();
      expect(mockLogger.error).toHaveBeenCalledWith(
        "Error clearing all sessions:",
        expect.any(Error)
      );
    });
  });
});
