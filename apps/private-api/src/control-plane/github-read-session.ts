import { ServiceUnavailableException } from "@nestjs/common";

function unavailable() {
  return new ServiceUnavailableException({ errorCode: "GITHUB_READ_SESSION_UNAVAILABLE",
    message: "Repository read session is unavailable." });
}

/** Integration-to-gateway upstream resource, never a public/worker credential.
 * The one-hour provider token is private RAM state; the scan uses a separate
 * ten-minute capability. No token getter or serializable secret property exists.
 */
export class GithubReadSession {
  #token?: string;
  #deadline: number;
  #delivered = false;
  #timer: ReturnType<typeof setTimeout>;
  #revoking?: Promise<void>;
  #deleteToken: (token: string) => Promise<void>;
  #onUnconfirmed: () => Promise<void>;
  readonly expiresAt: string;

  constructor(token: string, deadline: number, deleteToken: (token: string) => Promise<void>,
    onUnconfirmed: () => Promise<void>) {
    if (!token || token.length > 512 || /[\r\n]/.test(token) ||
        !Number.isFinite(deadline) || deadline <= Date.now() || deadline > Date.now()+600_000) throw unavailable();
    this.#token = token;
    this.#deadline = deadline;
    this.expiresAt = new Date(deadline).toISOString();
    this.#deleteToken = deleteToken;
    this.#onUnconfirmed = onUnconfirmed;
    this.#timer = setTimeout(() => { void this.revoke().catch(() => undefined); }, Math.max(1,deadline-Date.now()));
    this.#timer.unref?.();
  }

  toJSON(): never { throw unavailable(); }

  /** The caller supplies only the authenticated private gateway-channel writer. */
  async transfer(write: (frame: Buffer) => Promise<void>): Promise<void> {
    if (this.#delivered || !this.#token) throw unavailable();
    if (Date.now() >= this.#deadline) {
      await this.revoke();
      throw unavailable();
    }
    this.#delivered = true;
    const frame = Buffer.from(JSON.stringify({ upstreamToken: this.#token, expiresAt: this.expiresAt }));
    try {
      await write(frame);
      if (!this.#token || Date.now() >= this.#deadline) throw unavailable();
    } catch {
      await this.revoke();
      throw unavailable();
    } finally {
      frame.fill(0);
    }
  }

  async revoke(): Promise<void> {
    if (this.#revoking) return this.#revoking;
    if (!this.#token) return;
    const token = this.#token;
    clearTimeout(this.#timer);
    this.#revoking = (async () => {
      try {
        await this.#deleteToken(token);
      } catch {
        try { await this.#onUnconfirmed(); } catch { /* revoke still rejects; no handoff is authorized */ }
        throw unavailable();
      } finally {
        this.#token = undefined;
      }
    })();
    return this.#revoking;
  }
}
