import { createServer } from "node:http";
import { afterAll, beforeAll, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({
  inventory: vi.fn(),
  configure: vi.fn(),
  authorize: vi.fn(),
  resolve: vi.fn(),
  agent: vi.fn(),
}));
vi.mock("./model-connections.js", () => ({
  llmInventory: mocks.inventory,
  configureLlm: mocks.configure,
  resolveLlmConnection: mocks.resolve,
  rollbackLlm: vi.fn(),
}));
vi.mock("./http-utils.js", () => ({
  authorizeScopedGatewayHttpRequestOrReply: mocks.authorize,
  resolveOpenAiCompatibleHttpOperatorScopes: vi.fn(),
}));
vi.mock("../commands/agent.js", () => ({ agentCommandFromIngress: mocks.agent }));
vi.mock("../cli/deps.js", () => ({ createDefaultDeps: () => ({}) }));
vi.mock("../runtime.js", () => ({ defaultRuntime: {} }));
import { handleModelConnectionsHttpRequest } from "./model-connections-http.js";
const server = createServer((req, res) => {
  void handleModelConnectionsHttpRequest(req, res, { auth: { mode: "none" } }).then((handled) => {
    if (!handled) {
      res.statusCode = 404;
      res.end();
    }
  });
});
let base = "";
beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw Error();
  base = `http://127.0.0.1:${addr.port}/v1/model-connections/`;
});
afterAll(async () => {
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
});
beforeEach(() => {
  mocks.authorize.mockReset().mockResolvedValue({ cfg: {} });
  mocks.inventory.mockReset().mockResolvedValue({ providers: [], connections: [] });
  mocks.configure.mockReset();
});
it("requires admin configuration scope even for discovery", async () => {
  const response = await fetch(base + "inventory");
  expect(response.status).toBe(200);
  expect(mocks.authorize).toHaveBeenCalledWith(
    expect.objectContaining({ operatorMethod: "config.patch" }),
  );
});
it("never calls configuration after failed authentication", async () => {
  mocks.authorize.mockImplementation(async ({ res }) => {
    res.statusCode = 403;
    res.end();
    return null;
  });
  const response = await fetch(base + "configure", { method: "POST", body: "{}" });
  expect(response.status).toBe(403);
  expect(mocks.configure).not.toHaveBeenCalled();
});
it("redacts provider exceptions containing credential values", async () => {
  mocks.configure.mockRejectedValue(new Error("secret-demo-key private path /home/private"));
  const response = await fetch(base + "configure", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      operationId: "b131bb6a-d7aa-44bd-8b09-2121fb956828",
      name: "Account",
      provider: "installed",
      credential: "secret-demo-key",
    }),
  });
  expect(response.status).toBe(400);
  expect(await response.text()).toBe('{"ok":false,"error":"llm_operation_failed"}');
});
it("rejects unsupported custom endpoints before configuration", async () => {
  const response = await fetch(base + "configure", {
    method: "POST",
    body: JSON.stringify({
      operationId: "b131bb6a-d7aa-44bd-8b09-2121fb956828",
      name: "Account",
      provider: "installed",
      credential: "secret",
      endpoint: "http://internal",
    }),
  });
  expect(response.status).toBe(400);
  expect(mocks.configure).not.toHaveBeenCalled();
});
it("rejects mutations using GET", async () => {
  expect((await fetch(base + "configure")).status).toBe(405);
});

it("accepts a discovered native setup method without accepting client endpoint overrides", async () => {
  mocks.configure.mockResolvedValue({ id: "managed", version: 1 });
  const input = {
    operationId: "b131bb6a-d7aa-44bd-8b09-2121fb956828",
    name: "China plan",
    provider: "minimax",
    authMethodId: "api-cn",
    credential: "synthetic-test-key",
  };
  const response = await fetch(base + "configure", { method: "POST", body: JSON.stringify(input) });
  expect(response.status).toBe(200);
  expect(mocks.configure).toHaveBeenCalledWith({}, input);
  expect(await response.text()).not.toContain("synthetic-test-key");
});

it("tests each model in a replacement with its pinned transport while throttling duplicate probes", async () => {
  const managedProvider = {
    id: "regional",
    config: { baseUrl: "https://api.example.cn/anthropic", models: [] },
  };
  mocks.resolve.mockImplementation(async (_cfg, _id, model) => ({
    model: `regional/${model}`,
    profileId: "protected",
    managedProvider,
  }));
  mocks.agent.mockImplementation(async (input) => {
    const nonce = String(input.message).match(/[0-9a-f]{8}-[0-9a-f-]{27}/)?.[0];
    const model = String(input.model).split("/")[1];
    return {
      payloads: [{ text: JSON.stringify({ probe: nonce }) }],
      meta: {
        agentMeta: { provider: "regional", model },
        pendingToolCalls: [{ name: "llm_probe", arguments: JSON.stringify({ nonce }) }],
      },
    };
  });
  const probe = (modelId: string) =>
    fetch(base + "test", {
      method: "POST",
      body: JSON.stringify({
        connectionId: "regional-probe",
        version: 2,
        modelId,
        operationId: "b131bb6a-d7aa-44bd-8b09-2121fb956828",
      }),
    });
  const first = await probe("one");
  expect(first.status).toBe(200);
  expect(await first.json()).toMatchObject({
    result: { valid: true, capabilities: ["text", "json", "tools"] },
  });
  expect(
    mocks.agent.mock.calls.find(([input]) => input.message.startsWith("Call llm_probe"))?.[0]
      .modelRun,
  ).not.toBe(true);
  expect((await probe("two")).status).toBe(200);
  expect((await probe("one")).status).toBe(429);
  expect(mocks.agent).toHaveBeenCalledWith(
    expect.objectContaining({
      modelRun: true,
      managedProvider,
      pinnedAuthProfileId: "protected",
      disableModelFallback: true,
    }),
    expect.anything(),
    expect.anything(),
  );
});

it("returns a sanitized billing code for terminal and thrown managed test failures", async () => {
  mocks.resolve.mockResolvedValue({ model: "regional/one", profileId: "protected" });
  mocks.agent
    .mockResolvedValueOnce({
      meta: { error: { message: "402 Insufficient Balance: private provider details" } },
    })
    .mockRejectedValueOnce(new Error("402 insufficient balance: private provider details"));
  const probe = (modelId: string) =>
    fetch(base + "test", {
      method: "POST",
      body: JSON.stringify({
        connectionId: "billing-probe",
        version: 3,
        modelId,
        operationId: "b131bb6a-d7aa-44bd-8b09-2121fb956828",
      }),
    });
  for (const modelId of ["one", "two"]) {
    const response = await probe(modelId);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      result: { valid: false, capabilities: [], errorCode: "insufficient_balance" },
    });
  }
});

it("propagates an optional tool probe billing failure with combined sanitized usage", async () => {
  mocks.resolve.mockResolvedValue({ model: "regional/one", profileId: "protected" });
  mocks.agent
    .mockImplementationOnce(async (input) => ({
      payloads: [
        {
          text: JSON.stringify({
            probe: String(input.message).match(/[0-9a-f]{8}-[0-9a-f-]{27}/)?.[0],
          }),
        },
      ],
      meta: { agentMeta: { provider: "regional", model: "one", usage: { input: 3, output: 1 } } },
    }))
    .mockResolvedValueOnce({
      meta: {
        error: { message: "402 insufficient balance: private details" },
        agentMeta: { usage: { input: 7, output: 2 } },
      },
    });
  const response = await fetch(base + "test", {
    method: "POST",
    body: JSON.stringify({
      connectionId: "tool-billing-probe",
      version: 3,
      modelId: "one",
      operationId: "b131bb6a-d7aa-44bd-8b09-2121fb956828",
    }),
  });
  expect(await response.json()).toEqual({
    ok: true,
    result: {
      valid: false,
      capabilities: [],
      errorCode: "insufficient_balance",
      inputTokens: 10,
      outputTokens: 3,
    },
  });
});
