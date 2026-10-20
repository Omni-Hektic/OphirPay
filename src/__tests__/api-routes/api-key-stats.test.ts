// SPDX-License-Identifier: MIT

import { describe, it, expect, vi, beforeEach } from "vitest";
import { GET as getStatsRoute } from "@/app/api/keys/stats/route";
import { pruneApiKeyRequestLogs } from "@/lib/api-key-pruning";
import {
  getMetricsSnapshot,
  resetMetricsForTest,
  incApiKeyLogsPruned,
} from "@/lib/metrics-counters";

const prismaMocks = vi.hoisted(() => ({
  apiKeyFindMany: vi.fn(),
  apiKeyRequestLogFindMany: vi.fn(),
  apiKeyRequestLogDeleteMany: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  default: {
    apiKey: {
      findMany: prismaMocks.apiKeyFindMany,
    },
    apiKeyRequestLog: {
      findMany: prismaMocks.apiKeyRequestLogFindMany,
      deleteMany: prismaMocks.apiKeyRequestLogDeleteMany,
    },
  },
}));

const authMock = vi.hoisted(() => ({
  getAuthContext: vi.fn(),
}));

vi.mock("@/lib/auth-session", () => ({
  getAuthContext: authMock.getAuthContext,
}));

describe("GET /api/keys/stats — windowed stats query optimization (issue #1830)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMetricsForTest();
  });

  it("returns 401 when unauthenticated", async () => {
    authMock.getAuthContext.mockResolvedValueOnce(null);

    const req = new Request("https://ophirpay.com/api/keys/stats");
    const res = await getStatsRoute(req);

    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.error.message).toContain("Authentication required");
    expect(prismaMocks.apiKeyFindMany).not.toHaveBeenCalled();
    expect(prismaMocks.apiKeyRequestLogFindMany).not.toHaveBeenCalled();
  });

  it("returns 400 for invalid window parameter", async () => {
    authMock.getAuthContext.mockResolvedValueOnce({
      userId: "user-123",
      email: "user@example.com",
    });

    const req = new Request("https://ophirpay.com/api/keys/stats?window=invalid");
    const res = await getStatsRoute(req);

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.message).toContain("Window must be 24h, 7d, or 30d");
    expect(prismaMocks.apiKeyFindMany).not.toHaveBeenCalled();
  });

  it("queries only request logs within the inspection window using key IDs", async () => {
    authMock.getAuthContext.mockResolvedValueOnce({
      userId: "user-123",
      email: "user@example.com",
    });

    const now = new Date();
    const mockKeys = [
      {
        id: "key-1",
        name: "Production Key",
        prefix: "oph_prod",
        lastUsed: now,
        createdAt: new Date(now.getTime() - 86400000),
        expiresAt: null,
      },
      {
        id: "key-2",
        name: "Test Key",
        prefix: "oph_test",
        lastUsed: now,
        createdAt: new Date(now.getTime() - 86400000),
        expiresAt: null,
      },
    ];

    prismaMocks.apiKeyFindMany.mockResolvedValueOnce(mockKeys);
    prismaMocks.apiKeyRequestLogFindMany.mockResolvedValueOnce([
      { keyId: "key-1", createdAt: new Date(now.getTime() - 1000) },
      { keyId: "key-1", createdAt: new Date(now.getTime() - 5000) },
      { keyId: "key-2", createdAt: new Date(now.getTime() - 10000) },
    ]);

    const req = new Request("https://ophirpay.com/api/keys/stats?window=7d");
    const res = await getStatsRoute(req);

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.window).toBe("7d");
    expect(body.data.keys).toHaveLength(2);

    expect(prismaMocks.apiKeyRequestLogFindMany).toHaveBeenCalledWith({
      where: {
        keyId: { in: ["key-1", "key-2"] },
        createdAt: { gte: expect.any(Date) },
      },
      select: { keyId: true, createdAt: true },
    });
  });

  it("skips apiKeyRequestLog query when the user owns no API keys", async () => {
    authMock.getAuthContext.mockResolvedValueOnce({
      userId: "user-no-keys",
      email: "empty@example.com",
    });

    prismaMocks.apiKeyFindMany.mockResolvedValueOnce([]);

    const req = new Request("https://ophirpay.com/api/keys/stats?window=30d");
    const res = await getStatsRoute(req);

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.data.keys).toHaveLength(0);
    expect(prismaMocks.apiKeyRequestLogFindMany).not.toHaveBeenCalled();
  });
});

describe("pruneApiKeyRequestLogs — automated retention pruning (issue #1830)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetMetricsForTest();
  });

  it("prunes logs older than retention threshold in bounded batches and updates prometheus metric", async () => {
    // 1st batch returns 2 stale records
    prismaMocks.apiKeyRequestLogFindMany.mockResolvedValueOnce([
      { id: "log-1" },
      { id: "log-2" },
    ]);
    prismaMocks.apiKeyRequestLogDeleteMany.mockResolvedValueOnce({ count: 2 });

    // 2nd batch returns 0 records
    prismaMocks.apiKeyRequestLogFindMany.mockResolvedValueOnce([]);

    const result = await pruneApiKeyRequestLogs({
      retentionDays: 90,
      batchSize: 2,
      maxBatches: 5,
    });

    expect(result.prunedCount).toBe(2);
    expect(result.batchesExecuted).toBe(1);

    expect(prismaMocks.apiKeyRequestLogFindMany).toHaveBeenCalledWith({
      where: { createdAt: { lt: expect.any(Date) } },
      select: { id: true },
      take: 2,
    });

    expect(prismaMocks.apiKeyRequestLogDeleteMany).toHaveBeenCalledWith({
      where: { id: { in: ["log-1", "log-2"] } },
    });

    const metrics = getMetricsSnapshot();
    expect(metrics.api_key_logs_pruned_total).toBe(2);
  });

  it("handles empty database without pruning or throwing", async () => {
    prismaMocks.apiKeyRequestLogFindMany.mockResolvedValueOnce([]);

    const result = await pruneApiKeyRequestLogs({
      retentionDays: 90,
      batchSize: 1000,
    });

    expect(result.prunedCount).toBe(0);
    expect(result.batchesExecuted).toBe(0);
    expect(prismaMocks.apiKeyRequestLogDeleteMany).not.toHaveBeenCalled();

    const metrics = getMetricsSnapshot();
    expect(metrics.api_key_logs_pruned_total).toBe(0);
  });

  it("respects maxBatches limit when backlogged with stale logs", async () => {
    // Simulate 3 full batches
    for (let i = 0; i < 3; i++) {
      prismaMocks.apiKeyRequestLogFindMany.mockResolvedValueOnce([
        { id: `log-${i}-1` },
        { id: `log-${i}-2` },
      ]);
      prismaMocks.apiKeyRequestLogDeleteMany.mockResolvedValueOnce({ count: 2 });
    }

    const result = await pruneApiKeyRequestLogs({
      retentionDays: 90,
      batchSize: 2,
      maxBatches: 3,
    });

    expect(result.prunedCount).toBe(6);
    expect(result.batchesExecuted).toBe(3);
    expect(prismaMocks.apiKeyRequestLogFindMany).toHaveBeenCalledTimes(3);
    expect(prismaMocks.apiKeyRequestLogDeleteMany).toHaveBeenCalledTimes(3);

    const metrics = getMetricsSnapshot();
    expect(metrics.api_key_logs_pruned_total).toBe(6);
  });

  it("tracks incApiKeyLogsPruned helper correctly", () => {
    expect(getMetricsSnapshot().api_key_logs_pruned_total).toBe(0);
    incApiKeyLogsPruned(5);
    expect(getMetricsSnapshot().api_key_logs_pruned_total).toBe(5);
    incApiKeyLogsPruned(10);
    expect(getMetricsSnapshot().api_key_logs_pruned_total).toBe(15);
  });
});
