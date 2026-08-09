import type { IncomingMessage, ServerResponse } from "node:http";
import { hasRuntimeAvailableProviderAuth } from "../agents/model-auth.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { sendJson, sendMethodNotAllowed } from "./http-common.js";
import {
  authorizeScopedGatewayHttpRequestOrReply,
  resolveOpenAiCompatibleHttpOperatorScopes,
} from "./http-utils.js";

const READINESS_PATH = "/v1/openmanager/triage-workers/readiness";
const READINESS_OPERATOR_METHOD = "models.authStatus";

const workers = [
  { workerId: "minimax-primary", provider: "minimax-portal" },
  { workerId: "deepseek-primary", provider: "deepseek" },
] as const;

/**
 * Reports only whether the configured provider credential is usable by the
 * gateway. It intentionally excludes account identifiers, credentials, usage,
 * and provider error bodies so product admin UIs can safely gate activation.
 */
export async function handleOpenManagerTriageWorkerReadinessHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: {
    auth: ResolvedGatewayAuth;
    trustedProxies?: string[];
    allowRealIpFallback?: boolean;
    rateLimiter?: AuthRateLimiter;
  },
): Promise<boolean> {
  const pathname = new URL(req.url ?? "/", "http://localhost").pathname;
  if (pathname !== READINESS_PATH) return false;
  if (req.method !== "GET") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }
  const authResult = await authorizeScopedGatewayHttpRequestOrReply({
    req,
    res,
    auth: opts.auth,
    trustedProxies: opts.trustedProxies,
    allowRealIpFallback: opts.allowRealIpFallback,
    rateLimiter: opts.rateLimiter,
    operatorMethod: READINESS_OPERATOR_METHOD,
    resolveOperatorScopes: resolveOpenAiCompatibleHttpOperatorScopes,
  });
  if (!authResult) return true;
  const cfg = authResult.cfg;
  sendJson(res, 200, {
    ok: true,
    result: {
      workers: workers.map((worker) => ({
        workerId: worker.workerId,
        ready: hasRuntimeAvailableProviderAuth({
          provider: worker.provider,
          cfg,
          allowPluginSyntheticAuth: false,
        }),
      })),
    },
  });
  return true;
}
