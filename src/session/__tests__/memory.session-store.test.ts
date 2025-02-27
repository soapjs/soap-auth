import { MemorySessionStore } from "../memory.session-store";

interface MockSessionData {
  user?: {
    id?: string;
    name?: string;
  };
}

describe("MemorySessionStore", () => {
  let store: MemorySessionStore;

  beforeEach(() => {
    store = new MemorySessionStore();
  });

  describe("getSession", () => {
    it("should return null if session does not exist", async () => {
      const data = await store.getSession<MockSessionData>("nonExistent");
      expect(data).toBeNull();
    });

    it("should return the stored session data if present", async () => {
      await store.setSession<MockSessionData>("session1", {
        user: { id: "123", name: "John" },
      });

      const session = await store.getSession<MockSessionData>("session1");
      expect(session).toEqual({ user: { id: "123", name: "John" } });
    });
  });

  describe("setSession", () => {
    it("should store session data in memory", async () => {
      await store.setSession<MockSessionData>("session2", {
        user: { id: "abc", name: "Alice" },
      });
      const session = await store.getSession<MockSessionData>("session2");
      expect(session).toEqual({ user: { id: "abc", name: "Alice" } });
    });
  });

  describe("destroySession", () => {
    it("should delete the session from memory", async () => {
      await store.setSession<MockSessionData>("sessionDelete", {
        user: { id: "xyz", name: "Jane" },
      });

      await store.destroySession("sessionDelete");
      const session = await store.getSession<MockSessionData>("sessionDelete");
      expect(session).toBeNull();
    });

    it("should not throw if the session does not exist", async () => {
      await expect(store.destroySession("noSession")).resolves.not.toThrow();
    });
  });

  describe("touchSession", () => {
    it("should update the session data if it exists", async () => {
      await store.setSession<MockSessionData>("sessionTouch", {
        user: { id: "initial", name: "Old" },
      });

      await store.touchSession<MockSessionData>("sessionTouch", {
        user: { id: "updated", name: "New" },
      });

      const updated = await store.getSession<MockSessionData>("sessionTouch");
      expect(updated).toEqual({ user: { id: "updated", name: "New" } });
    });

    it("should create a new session if it doesn't exist (similar to setSession)", async () => {
      await store.touchSession<MockSessionData>("sessionNew", {
        user: { id: "newId", name: "New Name" },
      });

      const data = await store.getSession<MockSessionData>("sessionNew");
      expect(data).toEqual({ user: { id: "newId", name: "New Name" } });
    });
  });

  describe("getSessionIds", () => {
    it("should return an empty array if no sessions exist", async () => {
      const ids = await store.getSessionIds();
      expect(ids).toEqual([]);
    });

    it("should return all session IDs currently in memory", async () => {
      await store.setSession<MockSessionData>("id1", { user: { id: "one" } });
      await store.setSession<MockSessionData>("id2", { user: { id: "two" } });

      const ids = await store.getSessionIds();

      expect(ids).toContain("id1");
      expect(ids).toContain("id2");
      expect(ids.length).toBe(2);
    });
  });
});
