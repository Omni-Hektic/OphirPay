// SPDX-License-Identifier: MIT
import { withMetrics } from "@/lib/metrics-middleware";

/**
 * POST /api/auth/sudo — step up a wallet session for critical actions (#1389).
 *
 * The caller must already hold a valid session cookie. They submit the
 * challenge issued with a 403 `SUDO_REQUIRED` response plus the wallet's
 * signature over the sudo message. On success the session cookie is re-issued
 * with a fresh proof timestamp, opening a 15-minute sudo window.
 *
 * The signed message uses the `ophirpay:sudo:` domain (lib/challenge.ts), so a
 * login signature can never be replayed here.
 */

import {
  buildSessionCookie,
  readSessionCookie,
} from "@/lib/auth-session";
import {
  verifyChallengeToken,
  sudoChallengeMessage,
  verifyWalletSignature,
} from "@/lib/challenge";
import { SUDO_WINDOW_MS } from "@/lib/session-sudo";
import { successResponse, badRequestError, unauthorizedError } from "@/lib/api-response";
import { verifyCsrf } from "@/lib/csrf";
import { withRequestLogging } from "@/lib/request-logging";
import { enforceAuthRateLimit } from "@/lib/auth-rate-limit";

export const POST = withMetrics("POST /api/auth/sudo", withRequestLogging(async function POST(request: Request) {
  const csrfError = verifyCsrf(request);
  if (csrfError) return csrfError;

  const session = readSessionCookie(request);
  if (!session) {
    return unauthorizedError("A valid wallet session is required.");
  }

  // Throttle BEFORE any signature verification, per IP and per wallet.
  const rateLimited = await enforceAuthRateLimit(request, { publicKey: session.pk });
  if (rateLimited) return rateLimited;

  const body = (await request.json().catch(() => null)) as
    | { challenge?: string; signature?: string }
    | null;
  const challenge = typeof body?.challenge === "string" ? body.challenge : "";
  const signature = typeof body?.signature === "string" ? body.signature : "";
  if (!challenge || !signature) {
    return badRequestError("challenge and signature are required.");
  }

  if (!verifyChallengeToken(challenge, session.pk)) {
    return unauthorizedError("Challenge expired or invalid. Retry the action to get a fresh one.");
  }

  const message = sudoChallengeMessage(session.pk, challenge);
  if (!verifyWalletSignature(message, signature, session.pk)) {
    return unauthorizedError("Signature does not match the session wallet.");
  }

  const verifiedAt = Date.now();
  const response = successResponse({
    sudo: true,
    expiresAt: new Date(verifiedAt + SUDO_WINDOW_MS).toISOString(),
  });
  response.headers.set("Set-Cookie", buildSessionCookie(session.pk, session.nw, verifiedAt));
  return response;
}));
