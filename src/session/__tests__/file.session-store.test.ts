import { FileSessionStore } from "../file.session-store";
import fs from "fs/promises";
import path from "path";

jest.mock("fs/promises", () => ({
  mkdir: jest.fn(),
  readFile: jest.fn(),
  writeFile: jest.fn(),
  unlink: jest.fn(),
  readdir: jest.fn(),
}));

describe("FileSessionStore", () => {
  let store: FileSessionStore;
  const mockSessionsDir = "/mock/sessions";

  beforeEach(() => {
    store = new FileSessionStore(mockSessionsDir);
    jest.clearAllMocks();
  });

  describe("init", () => {
    it("should create the sessions directory recursively", async () => {
      await store.init();
      expect(fs.mkdir).toHaveBeenCalledWith(mockSessionsDir, {
        recursive: true,
      });
    });

    it("should catch and log errors if mkdir fails", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      (fs.mkdir as jest.Mock).mockRejectedValueOnce(new Error("mkdir error"));

      await store.init();
      expect(consoleSpy).toHaveBeenCalledWith(
        "Error initializing session directory:",
        expect.any(Error)
      );
      consoleSpy.mockRestore();
    });
  });

  describe("getSession", () => {
    it("should return parsed JSON if file read is successful", async () => {
      const mockData = { user: { id: "123" } };
      (fs.readFile as jest.Mock).mockResolvedValueOnce(
        JSON.stringify(mockData)
      );

      const session = await store.getSession("session123");
      expect(session).toEqual(mockData);
      expect(fs.readFile).toHaveBeenCalledWith(
        path.join(mockSessionsDir, "session123"),
        "utf8"
      );
    });

    it("should return null and log error if readFile fails", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      (fs.readFile as jest.Mock).mockRejectedValueOnce(new Error("read error"));

      const session = await store.getSession("badSession");
      expect(session).toBeNull();
      expect(consoleSpy).toHaveBeenCalledWith(
        "Error getting session:",
        expect.any(Error)
      );
      consoleSpy.mockRestore();
    });

    it("should return null if JSON parse fails", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      (fs.readFile as jest.Mock).mockResolvedValueOnce("invalid-json");

      const session = await store.getSession("corruptSession");

      expect(session).toBeNull();
      expect(consoleSpy).toHaveBeenCalledWith(
        "Error getting session:",
        expect.any(Error)
      );
      consoleSpy.mockRestore();
    });
  });

  describe("setSession", () => {
    it("should write stringified session data to a file", async () => {
      const mockData = { user: { id: "xyz" } };
      await store.setSession("sessionABC", mockData);

      expect(fs.writeFile).toHaveBeenCalledWith(
        path.join(mockSessionsDir, "sessionABC"),
        JSON.stringify(mockData),
        "utf8"
      );
    });

    it("should throw error if writeFile fails", async () => {
      (fs.writeFile as jest.Mock).mockRejectedValueOnce(
        new Error("write error")
      );

      await expect(
        store.setSession("sessionError", { user: { id: "1" } })
      ).rejects.toThrow("write error");
    });
  });

  describe("destroySession", () => {
    it("should unlink the file associated with the session ID", async () => {
      await store.destroySession("destroyMe");
      expect(fs.unlink).toHaveBeenCalledWith(
        path.join(mockSessionsDir, "destroyMe")
      );
    });

    it("should ignore ENOENT errors (file not found)", async () => {
      (fs.unlink as jest.Mock).mockRejectedValueOnce({ code: "ENOENT" });
      await expect(store.destroySession("notExists")).resolves.toBeUndefined();
    });

    it("should rethrow other errors", async () => {
      (fs.unlink as jest.Mock).mockRejectedValueOnce(new Error("unlink error"));
      await expect(store.destroySession("sessionX")).rejects.toThrow(
        "unlink error"
      );
    });
  });

  describe("touchSession", () => {
    it("should call setSession with updated data", async () => {
      const setSessionSpy = jest.spyOn(store, "setSession").mockResolvedValue();

      const newData = { user: { id: "touchMe" } };
      await store.touchSession("touchId", newData);

      expect(setSessionSpy).toHaveBeenCalledWith("touchId", newData);
    });
  });

  describe("getSessionIds", () => {
    it("should return the base names of files in the sessions directory", async () => {
      (fs.readdir as jest.Mock).mockResolvedValueOnce([
        { name: "abc", isFile: () => true },
        { name: "def.json", isFile: () => true },
        { name: "subdir", isFile: () => false },
      ]);

      const result = await store.getSessionIds();

      expect(result).toEqual(["abc", "def"]);
    });

    it("should throw if readdir fails", async () => {
      (fs.readdir as jest.Mock).mockRejectedValueOnce(
        new Error("readdir error")
      );
      await expect(store.getSessionIds()).rejects.toThrow("readdir error");
    });
  });
});
