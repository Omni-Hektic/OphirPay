"use client";
// SPDX-License-Identifier: MIT

import { useState } from "react";
import { Modal } from "@/components/ui/Modal";
import { Button } from "@/components/ui/Button";
import { useWallet } from "@/hooks/useMultiWallet";
import { getActiveWalletConnector } from "@/lib/wallets";
import { submitSudoReauth } from "@/lib/client-auth";
import { useToast } from "@/components/ui/Toast";

export interface SudoChallengeDetails {
  publicKey?: string;
  challenge?: string;
  message?: string;
  submitTo?: string;
  windowSeconds?: number;
}

interface SudoReauthModalProps {
  open: boolean;
  onClose: () => void;
  challenge?: SudoChallengeDetails | null;
  onSuccess: () => void | Promise<void>;
  actionName?: string;
}

/**
 * Frontend modal prompting quick Freighter re-signing before continuing (issue #1389).
 *
 * Appears when a sensitive administrative action returns 403 SUDO_REQUIRED.
 * Submits the wallet's cryptographic signature over the sudo challenge to
 * /api/auth/sudo, re-stamping the session for 15 minutes.
 */
export function SudoReauthModal({
  open,
  onClose,
  challenge,
  onSuccess,
  actionName = "this administrative action",
}: SudoReauthModalProps) {
  const toast = useToast();
  const { wallet } = useWallet();
  const [signing, setSigning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const connector = getActiveWalletConnector();
  const walletName = connector?.name ?? "Freighter";

  const handleSign = async () => {
    if (!challenge?.challenge || !challenge?.message) {
      setErrorMessage("No challenge available. Please retry the action.");
      return;
    }

    if (!connector?.signMessage) {
      setErrorMessage(
        `${walletName} does not support message signing. Connect with Freighter, xBull, or Albedo for administrative access.`
      );
      return;
    }

    setSigning(true);
    setErrorMessage(null);

    try {
      const signature = await connector.signMessage(challenge.message);
      if (!signature) {
        throw new Error("Signature was cancelled or declined in your wallet.");
      }

      const ok = await submitSudoReauth(challenge.challenge, signature);
      if (!ok) {
        throw new Error("Server rejected the sudo verification signature.");
      }

      toast.success(
        "Verification successful",
        "Sudo mode active for the next 15 minutes."
      );
      onClose();
      await onSuccess();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Re-authentication failed";
      setErrorMessage(msg);
      toast.error("Re-authentication failed", msg);
    } finally {
      setSigning(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={() => {
        if (!signing) onClose();
      }}
      title="Security Verification Required"
      size="sm"
    >
      <div className="space-y-4">
        <div className="flex items-center gap-3 p-3 rounded-lg bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800">
          <div className="w-8 h-8 rounded-full bg-amber-100 dark:bg-amber-900/50 flex items-center justify-center shrink-0">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              fill="none"
              viewBox="0 0 24 24"
              strokeWidth={1.5}
              stroke="currentColor"
              className="w-5 h-5 text-amber-700 dark:text-amber-400"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z"
              />
            </svg>
          </div>
          <div className="text-xs text-amber-800 dark:text-amber-200">
            <p className="font-semibold">Sudo Mode Protection</p>
            <p className="mt-0.5">
              Confirm your wallet identity to perform {actionName}.
            </p>
          </div>
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-300">
          Your active session needs a fresh cryptographic signature. Approving
          this request grants a 15-minute verification window without moving any
          funds.
        </p>

        {errorMessage && (
          <div className="p-2.5 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-800 text-xs text-red-700 dark:text-red-400">
            {errorMessage}
          </div>
        )}

        <div className="flex justify-end gap-3 pt-2">
          <Button
            variant="outline"
            onClick={onClose}
            disabled={signing}
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleSign}
            loading={signing}
          >
            Confirm with {walletName}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
