// SPDX-License-Identifier: MIT

import prisma from "@/lib/prisma";
import { incApiKeyLogsPruned } from "@/lib/metrics-counters";

export const DEFAULT_RETENTION_DAYS = 90;
export const DEFAULT_BATCH_SIZE = 1000;
export const DEFAULT_MAX_BATCHES = 10;

export interface PruneApiKeyLogsOptions {
  /** Retention duration in days (default: 90). */
  retentionDays?: number;
  /** Batch size per deletion chunk to prevent long table locks (default: 1000). */
  batchSize?: number;
  /** Maximum number of batches to process in a single invocation to bound execution time (default: 10). */
  maxBatches?: number;
  /** Explicit cutoff date override (useful for testing). */
  cutoffDate?: Date;
}

export interface PruneApiKeyLogsResult {
  prunedCount: number;
  batchesExecuted: number;
  cutoff: Date;
}

/**
 * Prunes historical ApiKeyRequestLog records older than the retention threshold
 * in bounded batches to prevent database connection bloat and table locks (issue #1830).
 */
export async function pruneApiKeyRequestLogs(
  options: PruneApiKeyLogsOptions = {}
): Promise<PruneApiKeyLogsResult> {
  const {
    retentionDays = DEFAULT_RETENTION_DAYS,
    batchSize = DEFAULT_BATCH_SIZE,
    maxBatches = DEFAULT_MAX_BATCHES,
    cutoffDate,
  } = options;

  const cutoff =
    cutoffDate ??
    new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

  // Defensive check for testing environments where prisma or prisma.apiKeyRequestLog may be partially mocked
  if (
    !prisma?.apiKeyRequestLog?.findMany ||
    !prisma?.apiKeyRequestLog?.deleteMany
  ) {
    return { prunedCount: 0, batchesExecuted: 0, cutoff };
  }

  let totalPruned = 0;
  let batchesExecuted = 0;

  for (let batch = 0; batch < maxBatches; batch++) {
    const staleLogs = await prisma.apiKeyRequestLog.findMany({
      where: {
        createdAt: { lt: cutoff },
      },
      select: { id: true },
      take: batchSize,
    });

    if (staleLogs.length === 0) {
      break;
    }

    const idsToDelete = staleLogs.map((log) => log.id);
    const deleteResult = await prisma.apiKeyRequestLog.deleteMany({
      where: {
        id: { in: idsToDelete },
      },
    });

    const count = deleteResult.count;
    totalPruned += count;
    batchesExecuted++;

    if (count > 0) {
      incApiKeyLogsPruned(count);
    }

    if (staleLogs.length < batchSize) {
      break;
    }
  }

  return {
    prunedCount: totalPruned,
    batchesExecuted,
    cutoff,
  };
}
