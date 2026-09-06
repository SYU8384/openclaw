import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, expect, it, vi } from "vitest";
const state = vi.hoisted(() => ({
  dir: "",
  providerReady: false,
  staticProviders: {} as Record<
    string,
    { models: Array<{ id: string; name: string; input: string[] }> }
  >,
  profiles: {} as Record<string, { type: "api_key"; provider: string; key: string }>,
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
