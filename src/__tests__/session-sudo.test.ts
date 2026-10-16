// SPDX-License-Identifier: MIT

import { describe, it, expect, vi, beforeEach } from "vitest";
import { Keypair } from "@stellar/stellar-sdk";

const { mockCreate, mockUpdateMany, mockGetAuthContext } = vi.hoisted(() => ({
  mockCreate: vi.fn(),
  mockUpdateMany: vi.fn(),
  mockGetAuthContext: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  default: {
    apiKey: { create: mockCreate, updateMany: mockUpdateMany, findMany: vi.fn() },
  },
}));

vi.mock("@/lib/auth-session", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth-session")>();
  return { ...actual, getAuthContext: mockGetAuthContext };
});

vi.mock("@/lib/auth-rate-limit", () => ({
  enforceAuthRateLimit: vi.fn().mockResolvedValue(null),
}));

import {
  SESSION_COOKIE_NAME,
  createSessionToken,
  parseSessionToken,
  buildSessionCookie,
} from "@/lib/auth-session";
import {
  challengeMessage,
  createChallengeToken,
  sudoChallengeMessage,
} from "@/lib/challenge";
import { SUDO_WINDOW_MS, isSudoFresh, requireSudo } from "@/lib/session-sudo";
import { generateCsrfToken } from "@/lib/csrf";
import { POST as sudoPost } from "@/app/api/auth/sudo/route";
import { POST as sessionPost } from "@/app/api/auth/session/route";
import {
  POST as createKey,
  PATCH as patchKey,
  DELETE as deleteKey,
} from "@/app/api/keys/route";
import { POST as rotateKey } from "@/app/api/keys/[id]/rotate/route";

const keypair = Keypair.random();
const PK = keypair.publicKey();

function sign(message: string, kp: Keypair = keypair): string {
  return kp.sign(Buffer.from(message, "utf8")).toString("base64");
}

function csrf(): Record<string, string> {
  const token = generateCsrfToken();
  return { "x-csrf-token": token, cookie: `__Host-csrf=${token}` };
}

/** Build a request carrying a session cookie whose proof time is `verifiedAt`. */
function withSession(
  url: string,
  init: { method: string; body?: unknown },
  verifiedAt: number | null
): Request {
  const sessionCookie = `${SESSION_COOKIE_NAME}=${createSessionToken(PK, "TESTNET", verifiedAt)}`;
  const c = csrf();
  return new Request(url, {
    method: init.method,
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": c["x-csrf-token"],
      cookie: `${c.cookie}; ${sessionCookie}`,
    },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

function cookieValueFrom(res: Response): string {
  const header = res.headers.get("set-cookie") ?? "";
  return header.split(";")[0].split("=").slice(1).join("=");
}

beforeEach(() => {
  vi.clearAllMocks();
  mockGetAuthContext.mockResolvedValue({ userId: "user-1", publicKey: PK });
  mockCreate.mockResolvedValue({ id: "key-1", name: "ci", prefix: "oph_abcd" });
  mockUpdateMany.mockResolvedValue({ count: 1 });
});

describe("isSudoFresh", () => {
  const now = 1_800_000_000_000;

  it("accepts a proof inside the 15 minute window", () => {
    expect(isSudoFresh({ vt: now - 60_000 }, now)).toBe(true);
    expect(isSudoFresh({ vt: now - SUDO_WINDOW_MS }, now)).toBe(true);
  });

  it("rejects a proof older than 15 minutes", () => {
    expect(isSudoFresh({ vt: now - SUDO_WINDOW_MS - 1 }, now)).toBe(false);
  });

  it("fails closed for legacy tokens with no proof timestamp", () => {
    expect(isSudoFresh({}, now)).toBe(false);
  });

  it("rejects a proof dated in the future beyond clock skew", () => {
    expect(isSudoFresh({ vt: now + 10 * 60_000 }, now)).toBe(false);
  });
});

describe("session token proof timestamp", () => {
  it("round-trips vt and omits it when null", () => {
    const stamped = parseSessionToken(createSessionToken(PK, "TESTNET", 12345));
    expect(stamped?.vt).toBe(12345);

    const legacy = parseSessionToken(createSessionToken(PK, "TESTNET", null));
    expect(legacy).not.toBeNull();
    expect(legacy?.vt).toBeUndefined();
  });

  it("defaults to a fresh proof for newly signed sessions", () => {
    const before = Date.now();
    const parsed = parseSessionToken(createSessionToken(PK, "TESTNET"));
    expect(parsed?.vt).toBeGreaterThanOrEqual(before);
  });
});

describe("requireSudo", () => {
  const url = "http://localhost/api/keys";

  it("lets API-key callers (no session cookie) through", () => {
    const res = requireSudo(new Request(url, { method: "POST" }));
    expect(res).toBeNull();
  });

  it("lets a freshly verified session through", () => {
    expect(requireSudo(withSession(url, { method: "POST" }, Date.now()))).toBeNull();
  });

  it("answers 403 SUDO_REQUIRED with a signable challenge when stale", async () => {
    const res = requireSudo(withSession(url, { method: "POST" }, Date.now() - SUDO_WINDOW_MS - 5_000));
    expect(res).not.toBeNull();
    expect(res!.status).toBe(403);

    const body = await res!.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("SUDO_REQUIRED");
    expect(body.error.details.publicKey).toBe(PK);
    expect(body.error.details.submitTo).toBe("/api/auth/sudo");
    expect(body.error.details.message).toBe(
      sudoChallengeMessage(PK, body.error.details.challenge)
    );
  });

  it("treats a legacy session with no proof timestamp as stale", async () => {
    const res = requireSudo(withSession(url, { method: "POST" }, null));
    expect(res?.status).toBe(403);
  });
});

describe("critical /api/keys mutations", () => {
  const url = "http://localhost/api/keys";
  const stale = () => Date.now() - SUDO_WINDOW_MS - 5_000;

  it("POST is blocked with SUDO_REQUIRED on a stale session and writes nothing", async () => {
    const res = await createKey(withSession(url, { method: "POST", body: { name: "ci" } }, stale()));
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("SUDO_REQUIRED");
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it("PATCH is blocked on a stale session", async () => {
    const res = await patchKey(
      withSession(url, { method: "PATCH", body: { id: "key-1", scopes: ["payments:read"] } }, stale())
    );
    expect(res.status).toBe(403);
    expect(mockUpdateMany).not.toHaveBeenCalled();
  });

  it("DELETE is blocked on a stale session", async () => {
    const res = await deleteKey(withSession(`${url}?id=key-1`, { method: "DELETE" }, stale()));
    expect(res.status).toBe(403);
    expect(mockUpdateMany).not.toHaveBeenCalled();
  });

  it("rotate is blocked on a stale session before touching the database", async () => {
    const res = await rotateKey(
      withSession(`${url}/key-1/rotate`, { method: "POST" }, stale()),
      { params: Promise.resolve({ id: "key-1" }) }
    );
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("SUDO_REQUIRED");
    expect(mockUpdateMany).not.toHaveBeenCalled();
  });

  it("POST proceeds on a fresh session", async () => {
    const res = await createKey(withSession(url, { method: "POST", body: { name: "ci" } }, Date.now()));
    expect(res.status).toBe(201);
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  it("still returns 401 (not a challenge) when unauthenticated", async () => {
    mockGetAuthContext.mockResolvedValue(null);
    const res = await createKey(withSession(url, { method: "POST", body: { name: "ci" } }, stale()));
    expect(res.status).toBe(401);
  });
});

describe("POST /api/auth/sudo", () => {
  const url = "http://localhost/api/auth/sudo";
  const stale = () => Date.now() - SUDO_WINDOW_MS - 5_000;

  it("re-stamps the session cookie after a valid sudo signature", async () => {
    const challenge = createChallengeToken(PK);
    const signature = sign(sudoChallengeMessage(PK, challenge));

    const before = Date.now();
    const res = await sudoPost(
      withSession(url, { method: "POST", body: { challenge, signature } }, stale())
    );
    expect(res.status).toBe(200);
    expect((await res.json()).data.sudo).toBe(true);

    const refreshed = parseSessionToken(cookieValueFrom(res));
    expect(refreshed?.vt).toBeGreaterThanOrEqual(before);
    expect(isSudoFresh(refreshed!)).toBe(true);
  });

  it("rejects a LOGIN signature replayed as a sudo signature", async () => {
    const challenge = createChallengeToken(PK);
    const signature = sign(challengeMessage(PK, challenge));

    const res = await sudoPost(
      withSession(url, { method: "POST", body: { challenge, signature } }, stale())
    );
    expect(res.status).toBe(401);
    expect(res.headers.get("set-cookie")).toBeNull();
  });

  it("rejects a signature from a different wallet", async () => {
    const challenge = createChallengeToken(PK);
    const signature = sign(sudoChallengeMessage(PK, challenge), Keypair.random());

    const res = await sudoPost(
      withSession(url, { method: "POST", body: { challenge, signature } }, stale())
    );
    expect(res.status).toBe(401);
  });

  it("rejects a challenge minted for another key", async () => {
    const other = Keypair.random();
    const challenge = createChallengeToken(other.publicKey());
    const signature = sign(sudoChallengeMessage(PK, challenge));

    const res = await sudoPost(
      withSession(url, { method: "POST", body: { challenge, signature } }, stale())
    );
    expect(res.status).toBe(401);
  });

  it("requires an existing session", async () => {
    const challenge = createChallengeToken(PK);
    const c = csrf();
    const res = await sudoPost(
      new Request(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-csrf-token": c["x-csrf-token"], cookie: c.cookie },
        body: JSON.stringify({ challenge, signature: sign(sudoChallengeMessage(PK, challenge)) }),
      })
    );
    expect(res.status).toBe(401);
  });

  it("requires challenge and signature", async () => {
    const res = await sudoPost(withSession(url, { method: "POST", body: {} }, stale()));
    expect(res.status).toBe(400);
  });
});

describe("session renewal cannot launder a stale session", () => {
  it("keeps the original proof time when renewing without a signature", async () => {
    const proofTime = Date.now() - SUDO_WINDOW_MS - 60_000;
    const res = await sessionPost(
      withSession(
        "http://localhost/api/auth/session",
        { method: "POST", body: { publicKey: PK, network: "TESTNET" } },
        proofTime
      )
    );
    expect(res.status).toBe(200);

    const renewed = parseSessionToken(cookieValueFrom(res));
    expect(renewed?.vt).toBe(proofTime);
    expect(isSudoFresh(renewed!)).toBe(false);
  });

  it("does not mint a proof for a renewed legacy session", async () => {
    const res = await sessionPost(
      withSession(
        "http://localhost/api/auth/session",
        { method: "POST", body: { publicKey: PK } },
        null
      )
    );
    expect(res.status).toBe(200);
    expect(parseSessionToken(cookieValueFrom(res))?.vt).toBeUndefined();
  });

  it("stamps a fresh proof when the wallet signs a login challenge", async () => {
    const challenge = createChallengeToken(PK);
    const signature = sign(challengeMessage(PK, challenge));
    const c = csrf();
    const before = Date.now();

    const res = await sessionPost(
      new Request("http://localhost/api/auth/session", {
        method: "POST",
        headers: { "Content-Type": "application/json", "x-csrf-token": c["x-csrf-token"], cookie: c.cookie },
        body: JSON.stringify({ publicKey: PK, challenge, signature }),
      })
    );
    expect(res.status).toBe(200);
    expect(parseSessionToken(cookieValueFrom(res))?.vt).toBeGreaterThanOrEqual(before);
  });
});

describe("buildSessionCookie", () => {
  it("embeds the supplied proof time", () => {
    const value = buildSessionCookie(PK, "TESTNET", 999).split(";")[0].split("=").slice(1).join("=");
    expect(parseSessionToken(value)?.vt).toBe(999);
  });
});
