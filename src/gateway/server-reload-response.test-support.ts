import chokidar from "chokidar";
import { expect, vi } from "vitest";
import { createDeferred } from "../../test/helpers/promise.js";
import {
  attachRuntimeConfigWriteApplication,
  createRuntimeConfigWriteApplication,
} from "../config/runtime-write-application.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import type { PreparedSecretsRuntimeSnapshot } from "../secrets/runtime.js";
import {
  captureConfigWriteListener,
  createConfigWriteListenerRef,
  createConfigWriteNotification,
  createValidConfigSnapshot,
} from "./server-reload-handlers.config.test-support.js";
import type { startManagedGatewayConfigReloader } from "./server-reload-managed.js";

type ManagedParams = Parameters<typeof startManagedGatewayConfigReloader>[0];

export async function runManagedResponseRestartScenario(
  transition: "direct" | "watcher echo" | "newer write" | "stop",
  {
    startReloader,
    prepareSecrets,
    setActiveTask,
  }: {
    startReloader: (
      params: Pick<ManagedParams, "initialConfig" | "readSnapshot" | "subscribeToWrites"> &
        Partial<ManagedParams>,
    ) => ReturnType<typeof startManagedGatewayConfigReloader>;
    prepareSecrets: (config: OpenClawConfig) => PreparedSecretsRuntimeSnapshot;
    setActiveTask: (active: boolean) => void;
  },
) {
  const waitForFast = (callback: () => unknown) => vi.waitFor(callback, { interval: 1 });
  // Restart deadlines use monotonic time; SQLite lease workers share real wall time.
  vi.useFakeTimers({
    toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "performance"],
  });
  const watcher = new chokidar.FSWatcher();
  const watch = vi.spyOn(chokidar, "watch").mockReturnValue(watcher);
  const initialConfig = {
    gateway: {
      port: 18_789,
      reload: {},
      auth: { mode: "token" as const, token: "old-token" },
    },
  } satisfies OpenClawConfig;
  let nextConfig = {
    gateway: {
      port: 18_790,
      reload: {},
      auth: { mode: "token" as const, token: "new-token" },
    },
  } satisfies OpenClawConfig;
  let persistedHash = "managed-response-gate";
  const writeListenerRef = createConfigWriteListenerRef();
  const requestRecoveryRestart = vi.fn(() => ({ status: "emitted" as const }));
  const activateRuntimeSecrets = vi.fn(async (config: OpenClawConfig) => prepareSecrets(config));
  const acceptTerminalConfig = vi.fn();
  const close = vi.fn();
  const responseSettled = createDeferred();
  const newerResponseSettled = createDeferred();
  const application = createRuntimeConfigWriteApplication(undefined, {
    responseSettled: responseSettled.promise,
  });
  setActiveTask(true);
  const reloader = startReloader({
    initialConfig,
    readSnapshot: vi.fn(async () => createValidConfigSnapshot(nextConfig, persistedHash)) as never,
    subscribeToWrites: captureConfigWriteListener(writeListenerRef),
    activateRuntimeSecrets: activateRuntimeSecrets as never,
    acceptTerminalConfig,
    requestRecoveryRestart,
    resolveSharedGatewaySessionGenerationForConfig: (config) =>
      typeof config.gateway?.auth?.token === "string" ? config.gateway.auth.token : undefined,
    sharedGatewaySessionGenerationState: { current: "old-token", required: null },
    clients: [
      {
        usesSharedGatewayAuth: true,
        sharedGatewaySessionGeneration: "old-token",
        socket: { close },
      },
    ],
  });
  const listener = writeListenerRef.current;
  if (!listener) {
    throw new Error("Expected config write listener to be registered");
  }
  const event = attachRuntimeConfigWriteApplication(
    createConfigWriteNotification(
      nextConfig,
      persistedHash,
      1,
      "runtime-managed-response-gate",
      "source-managed-response-gate",
    ),
    application,
  );

  try {
    listener(event);
    await vi.advanceTimersByTimeAsync(0);
    await expect(application.result).resolves.toBe("restart-pending");
    expect(application.claimed).toBe(true);
    expect(activateRuntimeSecrets).toHaveBeenCalledTimes(1);
    expect(requestRecoveryRestart).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();

    if (transition === "watcher echo") {
      watcher.emit("change", "/tmp/openclaw.json");
      await vi.advanceTimersByTimeAsync(300);
      await waitForFast(() => expect(acceptTerminalConfig).toHaveBeenCalledTimes(2));
    } else if (transition === "newer write") {
      nextConfig = { ...nextConfig, gateway: { ...nextConfig.gateway, port: 18_791 } };
      persistedHash = "newer-response-gate";
      const newerApplication = createRuntimeConfigWriteApplication(undefined, {
        responseSettled: newerResponseSettled.promise,
      });
      listener(
        attachRuntimeConfigWriteApplication(
          createConfigWriteNotification(
            nextConfig,
            persistedHash,
            2,
            "runtime-newer-gate",
            "source-newer-gate",
          ),
          newerApplication,
        ),
      );
      await vi.advanceTimersByTimeAsync(0);
      await expect(newerApplication.result).resolves.toBe("restart-pending");
      // Finishing the newest writer cannot release an older accepted response.
      newerResponseSettled.resolve();
    }

    // Even forced restart must wait for the response, after normal work drain expires.
    await vi.advanceTimersByTimeAsync(300_000);
    expect(requestRecoveryRestart).not.toHaveBeenCalled();

    if (transition === "stop") {
      await reloader.stop();
    }
    responseSettled.resolve();
    await vi.advanceTimersByTimeAsync(0);
    if (transition === "stop") {
      expect(requestRecoveryRestart).not.toHaveBeenCalled();
      expect(activateRuntimeSecrets).toHaveBeenCalledTimes(1);
    } else {
      // Timer advancement does not join the asynchronous restart preflight.
      await waitForFast(() => expect(requestRecoveryRestart).toHaveBeenCalledOnce());
      expect(requestRecoveryRestart).toHaveBeenCalledWith(expect.any(String), {
        force: true,
        reason: "config reload forced restart",
      });
    }
  } finally {
    responseSettled.resolve();
    newerResponseSettled.resolve();
    await reloader.stop();
    setActiveTask(false);
    watch.mockRestore();
    vi.useRealTimers();
  }
}
