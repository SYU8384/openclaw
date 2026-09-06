import { createServer } from "node:http";
import { afterAll, beforeAll, beforeEach, expect, it, vi } from "vitest";
const mocks = vi.hoisted(() => ({ inventory: vi.fn(), configure: vi.fn(), authorize: vi.fn() }));
vi.mock("./model-connections.js", () => ({
  llmInventory: mocks.inventory,
  configureLlm: mocks.configure,
  resolveLlmConnection: vi.fn(),
  rollbackLlm: vi.fn(),
}));
vi.mock("./http-utils.js", () => ({
  authorizeScopedGatewayHttpRequestOrReply: mocks.authorize,
  resolveOpenAiCompatibleHttpOperatorScopes: vi.fn(),
}));
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
