import { inspect } from "node:util";
import { GithubReadSession } from "../../src/control-plane/github-read-session";

describe("Private integration-to-gateway upstream read resource", () => {
  const token = "synthetic-upstream-not-a-worker-credential";
  afterEach(() => { jest.useRealTimers(); });

  it("has no serializable secret, transfers once and revokes idempotently", async () => {
    const revoke = jest.fn().mockResolvedValue(undefined);
    const session = new GithubReadSession(token,Date.now()+60_000,revoke,async()=>undefined);
    try {
      expect(inspect(session)).not.toContain(token);
      expect(() => JSON.stringify(session)).toThrow();
      let delivered = false;
      await session.transfer(async frame => {
        expect(JSON.parse(frame.toString()).upstreamToken).toBe(token);
        delivered = true;
      });
      expect(delivered).toBe(true);
      await expect(session.transfer(async()=>undefined)).rejects.toMatchObject({status:503});
      await Promise.all([session.revoke(),session.revoke()]);
      expect(revoke).toHaveBeenCalledTimes(1);
      await expect(session.transfer(async()=>undefined)).rejects.toMatchObject({status:503});
    } finally { await session.revoke(); }
  });

  it("automatically revokes at capability expiry without extending provider authority", async () => {
    jest.useFakeTimers();
    const revoke = jest.fn().mockResolvedValue(undefined);
    const session = new GithubReadSession(token,Date.now()+1000,revoke,async()=>undefined);
    await jest.advanceTimersByTimeAsync(1001);
    expect(revoke).toHaveBeenCalledTimes(1);
    await expect(session.transfer(async()=>undefined)).rejects.toMatchObject({status:503});
    await session.revoke();
  });

  it("revokes immediately if the wall clock passes expiry before a transfer", async () => {
    jest.useFakeTimers();
    const revoke = jest.fn().mockResolvedValue(undefined);
    const deadline = Date.now()+1000;
    const session = new GithubReadSession(token,deadline,revoke,async()=>undefined);
    jest.setSystemTime(deadline+1);
    await expect(session.transfer(async()=>undefined)).rejects.toMatchObject({status:503});
    expect(revoke).toHaveBeenCalledTimes(1);
  });

  it("revokes after a broken gateway channel and suppresses the writer's raw error", async () => {
    const revoke = jest.fn().mockResolvedValue(undefined);
    const session = new GithubReadSession(token,Date.now()+60_000,revoke,async()=>undefined);
    try {
      await session.transfer(async()=>{throw new Error(token);});
      throw new Error("Expected transfer failure");
    } catch (error) {
      expect(JSON.stringify(error)).not.toContain(token);
      expect(error).toMatchObject({status:503});
    }
    expect(revoke).toHaveBeenCalledTimes(1);
  });

  it("reports unconfirmed revocation once, drops its token and never returns provider errors", async () => {
    const unconfirmed = jest.fn().mockResolvedValue(undefined);
    const session = new GithubReadSession(token,Date.now()+60_000,async()=>{throw new Error(token);},unconfirmed);
    for(let i=0;i<2;i++) {
      try {
        await session.revoke();
        throw new Error("Expected revocation failure");
      } catch(error) {
        expect(error).toMatchObject({status:503});
        expect(JSON.stringify(error)).not.toContain(token);
      }
    }
    expect(unconfirmed).toHaveBeenCalledTimes(1);
    await expect(session.transfer(async()=>undefined)).rejects.toMatchObject({status:503});
  });

  it("does not report a successful transfer after concurrent upstream revocation", async () => {
    let release!:()=>void;
    const pending = new Promise<void>(resolve=>{release=resolve;});
    const session = new GithubReadSession(token,Date.now()+60_000,async()=>undefined,async()=>undefined);
    const transfer = session.transfer(async()=>pending);
    const checked = expect(transfer).rejects.toMatchObject({status:503});
    await session.revoke();
    release();
    await checked;
  });

  it("refuses upstream delivery authority longer than ten minutes", () => {
    expect(()=>new GithubReadSession(token,Date.now()+3_600_000,async()=>undefined,async()=>undefined)).toThrow();
  });
});
