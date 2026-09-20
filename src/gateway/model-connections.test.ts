import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({
  dir: "",
  providerReady: false,
  setupProviders: [] as Array<{
    id: string;
    label: string;
    auth: Array<{
      id: string;
      kind: string;
      label: string;
      managedApiKey?: { providerConfig: () => object };
    }>;
  }>,
  staticProviders: {} as Record<
    string,
    { models: Array<{ id: string; name: string; input: string[] }> }
  >,
  profiles: {} as Record<string, { type: "api_key"; provider: string; key: string }>,
}));
vi.mock("../plugins/providers.runtime.js", () => ({
  resolvePluginProviders: () => state.setupProviders,
}));
vi.mock("../config/paths.js", () => ({ resolveStateDir: () => state.dir }));
vi.mock("../agents/auth-profiles.js", () => ({
  ensureAuthProfileStore: () => ({ profiles: state.profiles }),
  resolveApiKeyForProfile: async ({ profileId }: { profileId: string }) =>
    state.profiles[profileId]?.key ? { apiKey: state.profiles[profileId].key } : null,
  upsertAuthProfileWithLock: async ({
    profileId,
    credential,
  }: {
    profileId: string;
    credential: { type: "api_key"; provider: string; key: string };
  }) => {
    state.profiles[profileId] = credential;
    return { profiles: state.profiles };
  },
}));
vi.mock("../agents/model-catalog.js", () => ({
  loadModelCatalog: async () => [
    { provider: "installed", id: "model", name: "Model", input: ["text"] },
  ],
}));
vi.mock("../agents/models-config.providers.implicit.js", () => ({
  resolveImplicitProviders: async () => state.staticProviders,
}));
vi.mock("../agents/model-auth.js", () => ({
  hasAvailableAuthForProvider: async () => state.providerReady,
}));
import { openOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import {
  configureLlm,
  llmInventory,
  resolveLlmConnection,
  rollbackLlm,
} from "./model-connections.js";
beforeAll(async () => {
  state.dir = await mkdtemp(join(tmpdir(), "openmanager-llm-test-"));
});
afterAll(async () => {
  await rm(state.dir, { recursive: true, force: true });
});
it("keeps credentials in the protected store and pins current, staged and rollback revisions independently", async () => {
  const first = await configureLlm(
    {},
    {
      operationId: "initial",
      provider: "installed",
      name: "Account",
      credential: "synthetic-secret-one",
    },
  );
  const selected = await resolveLlmConnection({}, first.id, "installed/model", 1);
  const second = await configureLlm(
    {},
    {
      operationId: "replace",
      connectionId: first.id,
      expectedVersion: 1,
      provider: "installed",
      name: "Account",
      credential: "synthetic-secret-two",
    },
  );
  expect(second.version).toBe(2);
  expect((await resolveLlmConnection({}, first.id, "installed/model", 1)).profileId).toBe(
    selected.profileId,
  );
  expect((await resolveLlmConnection({}, first.id, "installed/model", 2)).profileId).not.toBe(
    selected.profileId,
  );
  const rolled = await rollbackLlm(first.id, "initial", "rollback", 2);
  expect((await resolveLlmConnection({}, first.id, "model", rolled.version)).profileId).toBe(
    selected.profileId,
  );
  const db = openOpenClawStateDatabase({
    env: { ...process.env, OPENCLAW_STATE_DIR: state.dir },
  }).db;
  const ordinary = JSON.stringify(
    db.prepare("select payload_json from managed_model_connections").all(),
  );
  expect(ordinary).not.toContain("synthetic-secret");
  expect(JSON.stringify(await llmInventory({}))).not.toContain("synthetic-secret");
  await expect(resolveLlmConnection({}, first.id, "unregistered", 1)).rejects.toThrow(
    "unsupported_model",
  );
  await expect(resolveLlmConnection({}, first.id, "model", 99)).rejects.toThrow(
    "revision_unavailable",
  );
  await expect(
    configureLlm(
      {},
      {
        operationId: "stale",
        connectionId: first.id,
        expectedVersion: 1,
        provider: "installed",
        name: "Account",
        credential: "synthetic-secret-three",
      },
    ),
  ).rejects.toThrow("changed");
});

it("cannot overwrite an accepted credential through concurrent reused operation ids", async () => {
  const initial = await configureLlm(
    {},
    { operationId: "race-initial", provider: "installed", name: "Race", credential: "initial-key" },
  );
  const base = {
    operationId: "race-replace",
    connectionId: initial.id,
    expectedVersion: 1,
    provider: "installed",
    name: "Race",
  };
  const credentials = ["winner-or-loser-a", "winner-or-loser-b"];
  const results = await Promise.allSettled(
    credentials.map((credential) => configureLlm({}, { ...base, credential })),
  );
  expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
  const winner = results.findIndex((result) => result.status === "fulfilled");
  const selected = await resolveLlmConnection({}, initial.id, "model", 2);
  expect(state.profiles[selected.profileId!].key).toBe(credentials[winner]);
  await expect(configureLlm({}, { ...base, credential: credentials[1 - winner] })).rejects.toThrow(
    "Operation conflict",
  );
  await expect(
    configureLlm({}, { ...base, credential: credentials[winner] }),
  ).resolves.toMatchObject({ id: initial.id, version: 2 });
});

it("resolves imported environment-backed providers configured through the model allowlist", async () => {
  state.providerReady = true;
  try {
    const cfg = { agents: { defaults: { models: { "installed/model": {} } } } };
    const inventory = await llmInventory(cfg);
    const imported = inventory.connections.find((c) => c.operationId === "import");
    expect(imported).toBeDefined();
    await expect(resolveLlmConnection(cfg, imported!.id, "model", 1)).resolves.toEqual({
      model: "installed/model",
      profileId: undefined,
    });
  } finally {
    state.providerReady = false;
  }
});

it("retains configured installed providers with missing credentials using their static catalog", async () => {
  state.staticProviders = {
    offline: { models: [{ id: "model", name: "Offline model", input: ["text"] }] },
  };
  try {
    const cfg = { agents: { defaults: { models: { "offline/model": {} } } } };
    const inventory = await llmInventory(cfg);
    const connection = inventory.connections.find((c) => c.provider === "offline");
    expect(connection).toMatchObject({ ready: false, modelIds: ["model"] });
    await expect(resolveLlmConnection(cfg, connection!.id, "model", 1)).rejects.toThrow(
      "credential_unavailable",
    );
  } finally {
    state.staticProviders = {};
  }
});

it("discovers unconfigured API setup and isolates China/global transports through replacement and rollback", async () => {
  const model = { id: "regional-model", name: "Regional model", input: ["text"] };
  state.setupProviders = [
    {
      id: "regional",
      label: "Regional provider",
      auth: [
        {
          id: "cn",
          label: "China API",
          kind: "api_key",
          managedApiKey: {
            providerConfig: () => ({
              baseUrl: "https://api.example.cn/anthropic",
              api: "anthropic-messages",
              models: [model],
              apiKey: "must-not-copy",
              headers: { Authorization: "must-not-copy" },
            }),
          },
        },
        {
          id: "global",
          label: "Global API",
          kind: "api_key",
          managedApiKey: {
            providerConfig: () => ({
              baseUrl: "https://api.example.com/anthropic",
              api: "anthropic-messages",
              models: [model],
            }),
          },
        },
      ],
    },
    {
      id: "portal",
      label: "OAuth provider",
      auth: [{ id: "oauth", label: "Sign in", kind: "device_code" }],
    },
  ];
  try {
    const discovered = await llmInventory({});
    expect(
      discovered.providers.find((p) => p.id === "regional")?.authMethods.map((m) => m.id),
    ).toEqual(["cn", "global"]);
    const first = await configureLlm(
      {},
      {
        operationId: "cn-setup",
        provider: "regional",
        name: "China account",
        credential: "regional-secret",
        authMethodId: "cn",
      },
    );
    const second = await configureLlm(
      {},
      {
        operationId: "global-setup",
        connectionId: first.id,
        expectedVersion: 1,
        provider: "regional",
        name: "Global account",
        credential: "global-secret",
        authMethodId: "global",
      },
    );
    expect(
      (await resolveLlmConnection({}, first.id, model.id, 1)).managedProvider?.config.baseUrl,
    ).toBe("https://api.example.cn/anthropic");
    expect(
      (await resolveLlmConnection({}, first.id, model.id, 2)).managedProvider?.config.baseUrl,
    ).toBe("https://api.example.com/anthropic");
    const rollback = await rollbackLlm(first.id, "cn-setup", "regional-rollback", second.version);
    expect(
      (await resolveLlmConnection({}, first.id, model.id, rollback.version)).managedProvider?.config
        .baseUrl,
    ).toBe("https://api.example.cn/anthropic");
    const inventory = JSON.stringify(await llmInventory({}));
    expect(inventory).not.toMatch(/regional-secret|global-secret|must-not-copy/);
    const config = (await resolveLlmConnection({}, first.id, model.id, 1)).managedProvider?.config;
    expect(config).not.toHaveProperty("apiKey");
    expect(config).not.toHaveProperty("headers");
    await expect(
      configureLlm(
        {},
        {
          operationId: "bad-method",
          provider: "regional",
          name: "Account",
          credential: "secret",
          authMethodId: "oauth",
        },
      ),
    ).rejects.toThrow("Unsupported API-key");
    await expect(
      configureLlm(
        {},
        {
          operationId: "cn-setup",
          provider: "regional",
          name: "China account",
          credential: "regional-secret",
          authMethodId: "global",
        },
      ),
    ).rejects.toThrow("Operation conflict");
  } finally {
    state.setupProviders = [];
  }
});
