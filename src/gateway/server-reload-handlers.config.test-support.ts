import { vi } from "vitest";
import type { ConfigWriteNotification } from "../config/config.js";
import {
  attachRuntimeConfigWriteApplication,
  createRuntimeConfigWriteApplication,
} from "../config/runtime-write-application.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { GatewayReloadPlan } from "./config-reload-plan.js";
import type { GatewayCronState } from "./server-cron.js";
import type {
  GatewayPluginReloadResult,
  ManagedGatewayConfigReloaderParams,
} from "./server-reload-contracts.js";

type ConfigWriteListener = (event: ConfigWriteNotification) => void;
type ConfigWriteListenerRef = { current: ConfigWriteListener | null };

export function createValidConfigSnapshot(config: OpenClawConfig, hash: string) {
  return {
    path: "/tmp/openclaw.json",
    exists: true,
    raw: "{}",
    parsed: {},
    sourceConfig: config,
    resolved: config,
    valid: true,
    runtimeConfig: config,
    config,
    issues: [],
    warnings: [],
    legacyIssues: [],
    hash,
  };
}

export function createConfigWriteNotification(
  config: OpenClawConfig,
  persistedHash: string,
  revision: number,
  fingerprint: string,
  sourceFingerprint: string,
  overrides: Partial<ConfigWriteNotification> = {},
): ConfigWriteNotification {
  return {
    configPath: "/tmp/openclaw.json",
    sourceConfig: config,
    runtimeConfig: config,
    persistedHash,
    revision,
    fingerprint,
    sourceFingerprint,
    writtenAtMs: Date.now(),
    ...overrides,
  };
}

export function createConfigWriteListenerRef(): ConfigWriteListenerRef {
  return { current: null };
}

export function publishConfigWrite(listener: ConfigWriteListener, event: ConfigWriteNotification) {
  const application = createRuntimeConfigWriteApplication();
  listener(attachRuntimeConfigWriteApplication(event, application));
  return application.result;
}

export function captureConfigWriteListener(
  ref: ConfigWriteListenerRef,
  clearOnlyIfCurrent = true,
): ManagedGatewayConfigReloaderParams["subscribeToWrites"] {
  return (listener) => {
    ref.current = listener;
    return () => {
      if (!clearOnlyIfCurrent || ref.current === listener) {
        ref.current = null;
      }
    };
  };
}

export function createDirectConfigWriteFixture(initialConfig: OpenClawConfig) {
  let snapshot = createValidConfigSnapshot(initialConfig, "initial");
  const ref = createConfigWriteListenerRef();
  const subscribeToWrites: ManagedGatewayConfigReloaderParams["subscribeToWrites"] = (listener) =>
    captureConfigWriteListener(ref)((event) => {
      // Persist this write before notifying consumers; later writes replace the snapshot.
      snapshot = {
        ...createValidConfigSnapshot(event.sourceConfig, event.persistedHash),
        raw: JSON.stringify(event.sourceConfig),
        parsed: event.sourceConfig,
        resolved: event.sourceConfig,
        runtimeConfig: event.runtimeConfig,
        config: event.runtimeConfig,
      };
      listener(event);
    });
  return { ref, subscribeToWrites, readSnapshot: vi.fn(async () => snapshot) };
}

export function createDefaultGatewayReloadState(
  overrides: Partial<ReturnType<ManagedGatewayConfigReloaderParams["getState"]>> = {},
) {
  return {
    hooksConfig: {} as never,
    hookClientIpConfig: {} as never,
    heartbeatRunner: { stop: vi.fn(), updateConfig: vi.fn() } as never,
    cronState: createTestCronState(),
    ...overrides,
  };
}

export function createTestCronState(overrides: Partial<GatewayCronState> = {}): GatewayCronState {
  return {
    cron: { start: vi.fn(async () => {}), stop: vi.fn() } as never,
    storePath: "/tmp/cron.json",
    cronEnabled: false,
    reconcileExitWatchers: vi.fn(async () => {}),
    reconcileStreamWatchers: vi.fn(async () => {}),
    stopStreamWatchers: vi.fn(async () => {}),
    reconcileSystemJobs: vi.fn<GatewayCronState["reconcileSystemJobs"]>(async () => "converged"),
    ...overrides,
  };
}

export function createTestCronReconciliation() {
  const complete = vi.fn<() => Promise<void>>(async () => {});
  return {
    arm: vi.fn<() => { complete: () => Promise<void> }>(() => ({ complete })),
    complete,
    invalidate: vi.fn(),
  };
}

export function createCronRestartPlan(): GatewayReloadPlan {
  return createHotTailPlan({
    changedPaths: ["cron"],
    hotReasons: ["cron"],
    restartCron: true,
  });
}

export function createHotTailPlan(overrides: Partial<GatewayReloadPlan> = {}): GatewayReloadPlan {
  return {
    changedPaths: ["logging.level"],
    restartGateway: false,
    restartReasons: [],
    hotReasons: ["logging.level"],
    reloadHooks: false,
    restartGmailWatcher: false,
    restartCron: false,
    restartHeartbeat: false,
    reloadPlugins: false,
    restartChannels: new Set(),
    disposeMcpRuntimes: false,
    noopPaths: [],
    ...overrides,
  };
}

export function createGatewayRestartPlan(changedPath = "gateway.port"): GatewayReloadPlan {
  return createHotTailPlan({
    changedPaths: [changedPath],
    restartGateway: true,
    restartReasons: [changedPath],
    hotReasons: [],
  });
}

export function createPluginReloadPlan(): GatewayReloadPlan {
  return createHotTailPlan({
    changedPaths: ["plugins.enabled"],
    hotReasons: ["plugins.enabled"],
    reloadPlugins: true,
  });
}

export function makePluginReloadResult(
  overrides: Partial<GatewayPluginReloadResult> = {},
): GatewayPluginReloadResult {
  return {
    runtime: { operationId: "test-reload", generation: 1, pluginIds: [] },
    activeChannels: new Set(),
    ...overrides,
  };
}
