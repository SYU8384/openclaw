import { createHash, randomUUID } from "node:crypto";
import { resolveDefaultAgentDir } from "../agents/agent-scope.js";
import {
  ensureAuthProfileStore,
  resolveApiKeyForProfile,
  upsertAuthProfileWithLock,
} from "../agents/auth-profiles.js";
import { hasAvailableAuthForProvider } from "../agents/model-auth.js";
import { loadModelCatalog } from "../agents/model-catalog.js";
import { resolveStateDir } from "../config/paths.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import {
  getNodeSqliteKysely,
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
} from "../infra/kysely-sync.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import { openOpenClawStateDatabase } from "../state/openclaw-state-db.js";

export class LlmConnectionError extends Error {
  constructor(
    public code: "credential_unavailable" | "revision_unavailable" | "unsupported_model",
  ) {
    super(code);
  }
}

// Setup is an admin operation. Provider-owned definitions supply region/API defaults;
// browser input can select a method but never supply an arbitrary credential destination.
async function setupProviders(cfg: OpenClawConfig) {
  const { resolvePluginProviders } = await import("../plugins/providers.runtime.js");
  return resolvePluginProviders({
    config: cfg,
    mode: "setup",
    includeUntrustedWorkspacePlugins: false,
  });
}

function publicProviderConfig(config: import("../config/types.models.js").ModelProviderConfig) {
  const url = new URL(config.baseUrl);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash)
    throw new Error("Managed provider requires a credential-free HTTPS endpoint.");
  return {
    baseUrl: url.toString().replace(/\/$/, ""),
    ...(config.api ? { api: config.api } : {}),
    ...(config.authHeader !== undefined ? { authHeader: config.authHeader } : {}),
    models: config.models.map(({ id, name, reasoning, input, cost, contextWindow, maxTokens }) => ({
      id,
      name,
      reasoning,
      input,
      cost,
      contextWindow,
      maxTokens,
    })),
  };
}

type Revision = {
  authMethodId?: string;
  providerConfig?: import("../config/types.models.js").ModelProviderConfig;
  version: number;
  profileId?: string;
  operationId: string;
  configuredName?: string;
  expectedVersion?: number;
};
type Connection = { id: string; name: string; provider: string; revisions: Revision[] };
type Registry = { connections: Connection[] };
let snapshot: Registry | undefined;
function database() {
  return openOpenClawStateDatabase({
    env: { ...process.env, OPENCLAW_STATE_DIR: resolveStateDir() },
  });
}
function loadRegistryRow() {
  const { db } = database();
  const query = getNodeSqliteKysely<Pick<DB, "managed_model_connections">>(db);
  return executeSqliteQueryTakeFirstSync(
    db,
    query.selectFrom("managed_model_connections").select("payload_json").where("id", "=", 1),
  );
}
async function readRegistry() {
  snapshot ??= JSON.parse(loadRegistryRow()?.payload_json ?? '{"connections":[]}') as Registry;
  return snapshot;
}
async function updateRegistry<T>(mutate: (registry: Registry) => Promise<T>): Promise<T> {
  const old = loadRegistryRow()?.payload_json;
  const registry = JSON.parse(old ?? '{"connections":[]}') as Registry;
  const result = await mutate(registry);
  const { db } = database();
  const query = getNodeSqliteKysely<Pick<DB, "managed_model_connections">>(db);
  // Credentials use attempt-specific immutable profile ids. A losing CAS may leave
  // an unreferenced protected profile, but can never replace an applied credential.
  const payload = JSON.stringify(registry);
  const change =
    old === undefined
      ? executeSqliteQuerySync(
          db,
          query
            .insertInto("managed_model_connections")
            .values({ id: 1, payload_json: payload })
            .onConflict((oc) => oc.column("id").doNothing()),
        )
      : executeSqliteQuerySync(
          db,
          query
            .updateTable("managed_model_connections")
            .set({ payload_json: payload })
            .where("id", "=", 1)
            .where("payload_json", "=", old),
        );
  if (change.numAffectedRows !== 1n) throw new Error("Connection registry changed.");
  snapshot = registry;
  return result;
}
const stableId = (value: string) => createHash("sha256").update(value).digest("hex").slice(0, 32);

function configuredProviderIds(cfg: OpenClawConfig): Set<string> {
  const model = cfg.agents?.defaults?.model;
  const refs = [
    ...Object.keys(cfg.agents?.defaults?.models ?? {}),
    typeof model === "string" ? model : (model?.primary ?? ""),
  ];
  return new Set([
    ...Object.keys(cfg.models?.providers ?? {}),
    ...refs.filter((ref) => ref.includes("/")).map((ref) => ref.split("/")[0]),
  ]);
}

async function connectionCatalog(cfg: OpenClawConfig) {
  const catalog = [...(await loadModelCatalog({ config: cfg }))];
  // New connections remain resolvable without changing the global provider configuration.
  for (const connection of (await readRegistry()).connections) {
    for (const revision of connection.revisions) {
      for (const model of revision.providerConfig?.models ?? []) {
        if (!catalog.some((m) => m.provider === connection.provider && m.id === model.id))
          catalog.push({
            id: model.id,
            name: model.name,
            provider: connection.provider,
            input: model.input,
          });
      }
    }
  }
  const missing = [...configuredProviderIds(cfg)].filter(
    (id) => !catalog.some((m) => m.provider === id),
  );
  if (missing.length) {
    const { resolveImplicitProviders } =
      await import("../agents/models-config.providers.implicit.js");
    const providers = await resolveImplicitProviders({
      config: cfg,
      agentDir: resolveDefaultAgentDir(cfg),
      providerDiscoveryProviderIds: missing,
      providerDiscoveryEntriesOnly: true,
    });
    for (const [provider, config] of Object.entries(providers ?? {})) {
      for (const model of config.models ?? []) {
        if (!catalog.some((m) => m.provider === provider && m.id === model.id))
          catalog.push({ id: model.id, name: model.name, provider, input: model.input });
      }
    }
  }
  return catalog;
}

export async function llmInventory(cfg: OpenClawConfig) {
  const catalog = await connectionCatalog(cfg);
  const plugins = await setupProviders(cfg);
  const supported = plugins.filter((p) =>
    p.auth.some((a) => a.kind === "api_key" && a.managedApiKey),
  );
  for (const provider of supported) {
    for (const method of provider.auth) {
      for (const model of method.managedApiKey?.providerConfig()?.models ?? []) {
        if (!catalog.some((m) => m.provider === provider.id && m.id === model.id))
          catalog.push({
            id: model.id,
            name: model.name,
            provider: provider.id,
            input: model.input,
          });
      }
    }
  }
  const providerIds = [
    ...new Set([...catalog.map((m) => m.provider), ...supported.map((p) => p.id)]),
  ].sort();
  const store = ensureAuthProfileStore();
  const registry = await readRegistry();
  const imported: Connection[] = [];
  const configuredDefault = cfg.agents?.defaults?.model;
  const configuredRefs = [
    ...Object.keys(cfg.agents?.defaults?.models ?? {}),
    typeof configuredDefault === "string" ? configuredDefault : (configuredDefault?.primary ?? ""),
  ];
  for (const provider of providerIds) {
    const profiles = Object.entries(store.profiles).filter(
      ([id, c]) => c.provider === provider && !id.startsWith("managed-model:"),
    );
    if (profiles.length) {
      for (const [profileId] of profiles) {
        if (profileId.startsWith("managed-model:")) continue;
        imported.push({
          id: stableId(profileId),
          name: provider,
          provider,
          revisions: [{ version: 1, profileId, operationId: "import" }],
        });
      }
    } else if (
      cfg.models?.providers?.[provider] ||
      configuredRefs.some((ref) => ref.startsWith(`${provider}/`))
    ) {
      imported.push({
        id: stableId(`provider:${provider}`),
        name: provider,
        provider,
        revisions: [{ version: 1, operationId: "import" }],
      });
    }
  }
  const connections = [
    ...registry.connections,
    ...imported.filter((c) => !registry.connections.some((x) => x.id === c.id)),
  ];
  const defaultConfig = cfg.agents?.defaults?.model;
  const defaultModel = typeof defaultConfig === "string" ? defaultConfig : defaultConfig?.primary;
  return {
    defaultModel,
    providers: providerIds.map((id) => ({
      id,
      name: plugins.find((p) => p.id === id)?.label ?? id,
      authMethods:
        plugins
          .find((p) => p.id === id)
          ?.auth.filter((a) => a.kind === "api_key" && a.managedApiKey)
          .map((a) => ({ id: a.id, label: a.label, hint: a.hint })) ??
        (cfg.models?.providers?.[id]
          ? [{ id: "configured-api", label: "API key (configured endpoint)", hint: undefined }]
          : []),
      models: catalog
        .filter((m) => m.provider === id)
        .map((m) => ({
          id: m.id,
          name: m.name,
          capabilities: ["text", ...(m.input?.includes("image") ? ["image"] : [])],
        })),
    })),
    connections: await Promise.all(
      connections.map(async (c) => {
        const revision = c.revisions.at(-1)!;
        let ready = false;
        try {
          ready = revision.profileId
            ? Boolean(await resolveApiKeyForProfile({ cfg, store, profileId: revision.profileId }))
            : await hasAvailableAuthForProvider({ cfg, provider: c.provider });
        } catch {
          /* Readiness never returns credential errors or secret values. */
        }
        return {
          id: c.id,
          name: c.name,
          provider: c.provider,
          accountScope: `provider:${c.provider}`,
          runtimeRef: c.id,
          version: revision.version,
          operationId: revision.operationId,
          authMethodId: revision.authMethodId,
          endpoint: revision.providerConfig?.baseUrl,
          ready,
          modelIds: catalog.filter((m) => m.provider === c.provider).map((m) => m.id),
        };
      }),
    ),
  };
}

export async function resolveLlmConnection(
  cfg: OpenClawConfig,
  id: string,
  model: string,
  version?: number,
) {
  const stored = (await readRegistry()).connections.find((c) => c.id === id);
  const store = ensureAuthProfileStore();
  const imported = Object.entries(store.profiles).find(([key]) => stableId(key) === id);
  const catalog = await connectionCatalog(cfg);
  const provider =
    stored?.provider ??
    imported?.[1].provider ??
    [...configuredProviderIds(cfg)].find(
      (p) => catalog.some((m) => m.provider === p) && stableId(`provider:${p}`) === id,
    );
  const revision = stored?.revisions.find(
    (r) => r.version === (version ?? stored.revisions.at(-1)?.version),
  );
  if (!provider || (stored && !revision) || (!stored && version !== undefined && version !== 1))
    throw new LlmConnectionError("revision_unavailable");
  const profileId = revision?.profileId ?? imported?.[0];
  const key = model.startsWith(`${provider}/`) ? model.slice(provider.length + 1) : model;
  if (!catalog.some((m) => m.provider === provider && m.id === key))
    throw new LlmConnectionError("unsupported_model");
  const ready = profileId
    ? Boolean(await resolveApiKeyForProfile({ cfg, store, profileId }))
    : await hasAvailableAuthForProvider({ cfg, provider });
  if (!ready) throw new LlmConnectionError("credential_unavailable");
  return {
    model: `${provider}/${key}`,
    profileId,
    ...(revision?.providerConfig
      ? { managedProvider: { id: provider, config: revision.providerConfig } }
      : {}),
  };
}

export async function configureLlm(
  cfg: OpenClawConfig,
  input: {
    operationId: string;
    connectionId?: string;
    expectedVersion?: number;
    provider: string;
    name: string;
    credential: string;
    authMethodId?: string;
  },
) {
  const inventory = await llmInventory(cfg);
  if (!inventory.providers.some((p) => p.id === input.provider))
    throw new Error("Provider is not installed.");
  const plugin = (await setupProviders(cfg)).find((p) => p.id === input.provider);
  const method = input.authMethodId
    ? plugin?.auth.find(
        (a) => a.id === input.authMethodId && a.kind === "api_key" && a.managedApiKey,
      )
    : undefined;
  const configuredMethod =
    !plugin && input.authMethodId === "configured-api"
      ? cfg.models?.providers?.[input.provider]
      : undefined;
  if (input.authMethodId && !method && !configuredMethod)
    throw new Error("Unsupported API-key setup method.");
  // Preserve legacy API-key clients, but never accept a key for an OAuth-only provider.
  if (plugin && !plugin.auth.some((a) => a.kind === "api_key"))
    throw new Error("This provider requires browser sign-in.");
  const nativeConfig = method?.managedApiKey?.providerConfig() ?? configuredMethod;
  const providerConfig = nativeConfig ? publicProviderConfig(nativeConfig) : undefined;
  return updateRegistry(async (registry) => {
    const completed = registry.connections.find((c) =>
      c.revisions.some((v) => v.operationId === input.operationId),
    );
    if (completed) {
      const revision = completed.revisions.find((v) => v.operationId === input.operationId)!;
      const credential = revision.profileId
        ? await resolveApiKeyForProfile({
            cfg,
            store: ensureAuthProfileStore(),
            profileId: revision.profileId,
          })
        : null;
      if (
        revision.authMethodId !== input.authMethodId ||
        revision.configuredName !== input.name ||
        revision.expectedVersion !== input.expectedVersion ||
        credential?.apiKey !== input.credential ||
        completed.provider !== input.provider ||
        (input.connectionId && completed.id !== input.connectionId)
      )
        throw new Error("Operation conflict.");
      return {
        id: completed.id,
        version: completed.revisions.find((v) => v.operationId === input.operationId)!.version,
        accountScope: `provider:${completed.provider}`,
      };
    }
    let c = registry.connections.find((c) => c.id === input.connectionId);
    if (!c && input.connectionId) {
      const imported = inventory.connections.find((c) => c.id === input.connectionId);
      if (!imported) throw new Error("Unknown connection.");
      const profileId = Object.keys(ensureAuthProfileStore().profiles).find(
        (key) => stableId(key) === imported.id,
      );
      c = {
        id: imported.id,
        name: imported.name,
        provider: imported.provider,
        revisions: [{ version: 1, profileId, operationId: "import" }],
      };
      registry.connections.push(c);
    }
    if (
      c &&
      (c.provider !== input.provider || c.revisions.at(-1)!.version !== input.expectedVersion)
    )
      throw new Error("Connection changed.");
    if (!c) {
      c = { id: randomUUID(), name: input.name, provider: input.provider, revisions: [] };
      registry.connections.push(c);
    }
    const version = (c.revisions.at(-1)?.version ?? 0) + 1;
    const profileId = `managed-model:${c.id}:${version}:${randomUUID()}`;
    // Immutable credential revisions preserve rollback; ordinary metadata stores references only.
    const written = await upsertAuthProfileWithLock({
      profileId,
      credential: { type: "api_key", provider: c.provider, key: input.credential },
    });
    if (!written) throw new Error("Credential storage failed.");
    c.name = input.name;
    c.revisions.push({
      version,
      profileId,
      operationId: input.operationId,
      configuredName: input.name,
      expectedVersion: input.expectedVersion,
      authMethodId: input.authMethodId,
      providerConfig: providerConfig ?? c.revisions.at(-1)?.providerConfig,
    });
    return { id: c.id, version, accountScope: `provider:${c.provider}` };
  });
}

export async function rollbackLlm(
  connectionId: string,
  targetOperationId: string,
  operationId: string,
  expectedVersion: number,
) {
  return updateRegistry(async (registry) => {
    const c = registry?.connections.find((c) => c.id === connectionId);
    const previous = c?.revisions.find((v) => v.operationId === targetOperationId);
    if (!c || !previous) throw new Error("Rollback revision unavailable.");
    const completed = c.revisions.find((v) => v.operationId === operationId);
    if (completed) return { version: completed.version };
    if (c.revisions.at(-1)!.version !== expectedVersion) throw new Error("Connection changed.");
    const version = c.revisions.at(-1)!.version + 1;
    c.revisions.push({ ...previous, version, operationId });
    return { version };
  });
}
