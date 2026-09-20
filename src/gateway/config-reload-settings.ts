// Gateway reload settings resolver.
// Normalizes reload mode and debounce config for watcher/reload handlers.
import type { GatewayReloadMode } from "../config/types.gateway.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";

type GatewayReloadSettings = {
  mode: GatewayReloadMode;
  debounceMs: number;
};

const DEFAULT_RELOAD_SETTINGS: GatewayReloadSettings = {
  mode: "hybrid",
  debounceMs: 300,
};

/** Resolves gateway reload mode/debounce from config with bounded defaults. */
export function resolveGatewayReloadSettings(cfg: OpenClawConfig): GatewayReloadSettings {
  const rawMode = cfg.gateway?.reload?.mode;
  const mode = rawMode === "off" || rawMode === "hybrid" ? rawMode : DEFAULT_RELOAD_SETTINGS.mode;
  return { mode, debounceMs: DEFAULT_RELOAD_SETTINGS.debounceMs };
}

export function resolveChokidarUsePolling(degradedToPolling: boolean): boolean {
  const envPoll = process.env.CHOKIDAR_USEPOLLING;
  if (envPoll !== undefined) {
    const envLower = envPoll.toLowerCase();
    if (envLower === "false" || envLower === "0") {
      return false;
    }
    if (envLower === "true" || envLower === "1") {
      return true;
    }
    return Boolean(envLower);
  }
  return Boolean(process.env.VITEST) || degradedToPolling;
}
