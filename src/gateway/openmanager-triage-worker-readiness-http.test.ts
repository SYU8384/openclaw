import { createServer } from "node:http";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { ResolvedGatewayAuth } from "./auth.js";
import { handleOpenManagerTriageWorkerReadinessHttpRequest } from "./openmanager-triage-worker-readiness-http.js";

const hasAuth = vi.hoisted(() => vi.fn());

vi.mock("../agents/model-auth.js", () => ({ hasAvailableAuthForProvider: hasAuth }));
vi.mock("./http-utils.js", () => ({
  authorizeScopedGatewayHttpRequestOrReply: vi.fn(async () => ({ cfg: {} })),
  resolveOpenAiCompatibleHttpOperatorScopes: vi.fn(),
}));

let server: ReturnType<typeof createServer> | undefined;
let port = 0;

beforeAll(async () => {
  server = createServer((req, res) => {
    void handleOpenManagerTriageWorkerReadinessHttpRequest(req, res, {
      auth: { mode: "none" } as ResolvedGatewayAuth,
    }).then((handled) => {
      if (!handled) {
        res.statusCode = 404;
        res.end();
      }
    });
  });
  await new Promise<void>((resolve, reject) =>
    server?.listen(0, "127.0.0.1", () => {
      const address = server?.address();
      if (!address || typeof address === "string") return reject(new Error("no TCP address"));
      port = address.port;
      resolve();
    }),
  );
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server?.close((error) => (error ? reject(error) : resolve())),
  );
});

beforeEach(() => {
  hasAuth.mockReset().mockImplementation(async ({ provider }) => provider === "minimax-portal");
});

describe("OpenManager triage worker readiness HTTP", () => {
  it("returns only per-worker ready booleans", async () => {
    const response = await fetch(
      `http://127.0.0.1:${port}/v1/openmanager/triage-workers/readiness`,
    );
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      ok: true,
      result: {
        workers: [
          { workerId: "minimax-primary", ready: true },
          { workerId: "deepseek-primary", ready: false },
        ],
      },
    });
  });

  it("accepts only GET", async () => {
    const response = await fetch(
      `http://127.0.0.1:${port}/v1/openmanager/triage-workers/readiness`,
      { method: "POST" },
    );
    expect(response.status).toBe(405);
  });
});
