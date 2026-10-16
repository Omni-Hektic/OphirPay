// SPDX-License-Identifier: MIT

/**
 * Sudo mode for critical administrative actions (issue #1389).
 *
 * A wallet session cookie lives for 7 days, so an unattended browser would
 * otherwise let anyone perform high-impact mutations (API key creation,
 * scope changes, revocation) without the wallet's private key. Sudo mode
 * requires the wallet to have cryptographically proved key ownership within
 * the last 15 minutes before such an action proceeds.
 *
 * Flow:
 *   1. A critical route calls `requireSudo(request)`.
 *   2. If the session's last proof (`vt`) is older than SUDO_WINDOW_MS, the
 *      route answers 403 `SUDO_REQUIRED` with a challenge payload.
 *   3. The client has the wallet sign `details.message` and POSTs
 *      { challenge, signature } to /api/auth/sudo, which re-stamps the
 *      session cookie, and then retries the original request.
 *
 * Machine-to-machine API keys are exempt: they are explicit bearer
 * credentials with their own scopes and cannot produce wallet signatures
 * (same reasoning as the CSRF exemption in lib/csrf.ts).
 *
 * Fail closed: legacy session tokens with no proof timestamp, or a timestamp
 * in the future, are treated as stale.
 */

import { errorResponse } from "@/lib/api-response";
import { ERROR_CODES } from "@/lib/error-codes";
import { readSessionCookie, type SessionPayload } from "@/lib/auth-session";
import { createChallengeToken, sudoChallengeMessage } from "@/lib/challenge";

/** How long a wallet signature keeps a session "fresh" for critical actions. */
export const SUDO_WINDOW_MS = 15 * 60 * 1000;

/** Tolerated clock skew before a future-dated proof is considered invalid. */
const CLOCK_SKEW_MS = 60 * 1000;

/** Endpoint the client submits the signed sudo challenge to. */
export const SUDO_ENDPOINT = "/api/auth/sudo";

/**
 * True when the session's last wallet proof is within the sudo window.
 * `now` is injectable for deterministic tests.
 */
export function isSudoFresh(
  session: Pick<SessionPayload, "vt">,
  now: number = Date.now()
): boolean {
  const vt = session.vt;
  if (typeof vt !== "number" || !Number.isFinite(vt)) return false;
  if (vt > now + CLOCK_SKEW_MS) return false;
  return now - vt <= SUDO_WINDOW_MS;
}

/**
 * Enforce sudo mode for a critical action.
 *
 * Returns `null` when the action may proceed, or a 403 `SUDO_REQUIRED`
 * Response (carrying a signable challenge) when re-authentication is needed.
 * Call it AFTER authentication and CSRF checks so unauthenticated callers
 * still receive 401 rather than a challenge.
 */
export function requireSudo(request: Request): Response | null {
  const session = readSessionCookie(request);
  // No wallet session cookie: the caller authenticated with an API key (or is
  // unauthenticated, which the route's own auth check already rejects).
  if (!session) return null;

  if (isSudoFresh(session)) return null;

  const challenge = createChallengeToken(session.pk);
  return errorResponse(
    ERROR_CODES.SUDO_REQUIRED,
    "Re-authentication required: sign the challenge with your wallet to continue.",
    403,
    {
      publicKey: session.pk,
      challenge,
      message: sudoChallengeMessage(session.pk, challenge),
      submitTo: SUDO_ENDPOINT,
      windowSeconds: SUDO_WINDOW_MS / 1000,
    }
  );
}
