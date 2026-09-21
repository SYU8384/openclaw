import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { readJsonBodyOrError, sendJson, sendMethodNotAllowed } from "./http-common.js";
import {
  authorizeScopedGatewayHttpRequestOrReply,
  resolveOpenAiCompatibleHttpOperatorScopes,
} from "./http-utils.js";
import { classifyManagedLlmError, managedLlmResultIdentity } from "./managed-model-result.js";
import {
  configureLlm,
  LlmConnectionError,
  llmInventory,
  resolveLlmConnection,
  rollbackLlm,
} from "./model-connections.js";

const imageProbe =
  "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAIAAABLbSncAAAAEklEQVR4nGP4z8CAFWEXHbQSACj/P8Fu7N9hAAAAAElFTkSuQmCC";
const identifier = z.string().min(1).max(160);
const configure = z
  .object({
    operationId: z.string().uuid(),
    connectionId: identifier.optional(),
    expectedVersion: z.number().int().positive().optional(),
    provider: identifier,
    name: z.string().trim().min(1).max(100),
    credential: z.string().min(1).max(16384),
    authMethodId: identifier.optional(),
  })
  .strict();
const test = z
  .object({
    connectionId: identifier,
    modelId: identifier,
    operationId: z.string().uuid(),
    version: z.number().int().positive().optional(),
  })
  .strict();
const rollback = z
  .object({
    connectionId: identifier,
    operationId: z.string().uuid(),
    targetOperationId: identifier,
    expectedVersion: z.number().int().positive(),
  })
  .strict();
const readiness = z
  .object({
    connections: z
      .array(
        z
          .object({ id: identifier, version: z.number().int().positive(), model: identifier })
          .strict(),
      )
      .max(100),
  })
  .strict();
const testsInFlight = new Set<string>();
const lastTest = new Map<string, number>();

function managedLlmUsage(result: unknown): { inputTokens?: number; outputTokens?: number } {
  const usage = (
    result as { meta?: { agentMeta?: { usage?: { input?: unknown; output?: unknown } } } } | null
  )?.meta?.agentMeta?.usage;
  const count = (value: unknown) =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  const inputTokens = count(usage?.input);
  const outputTokens = count(usage?.output);
  return {
    ...(inputTokens === undefined ? {} : { inputTokens }),
    ...(outputTokens === undefined ? {} : { outputTokens }),
  };
}

function combineManagedLlmUsage(...results: unknown[]): {
  inputTokens?: number;
  outputTokens?: number;
} {
  let inputTokens = 0;
  let outputTokens = 0;
  let hasInputTokens = false;
  let hasOutputTokens = false;
  for (const result of results) {
    const usage = managedLlmUsage(result);
    if (usage.inputTokens !== undefined) {
      inputTokens += usage.inputTokens;
      hasInputTokens = true;
    }
    if (usage.outputTokens !== undefined) {
      outputTokens += usage.outputTokens;
      hasOutputTokens = true;
    }
  }
  return {
    ...(hasInputTokens ? { inputTokens } : {}),
    ...(hasOutputTokens ? { outputTokens } : {}),
  };
}

export async function handleModelConnectionsHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: {
    auth: ResolvedGatewayAuth;
    pathPrefix?: string;
    trustedProxies?: string[];
    allowRealIpFallback?: boolean;
    rateLimiter?: AuthRateLimiter;
  },
): Promise<boolean> {
  const path = new URL(req.url ?? "/", "http://localhost").pathname;
  const prefix = opts.pathPrefix ?? "/v1/model-connections/";
  if (!path.startsWith(prefix)) return false;
  const action = path.slice(prefix.length);
  const auth = await authorizeScopedGatewayHttpRequestOrReply({
    req,
    res,
    ...opts,
    operatorMethod: "config.patch",
    resolveOperatorScopes: resolveOpenAiCompatibleHttpOperatorScopes,
  });
  if (!auth) return true;
  const method = action === "inventory" ? "GET" : "POST";
  if (req.method !== method) {
    sendMethodNotAllowed(res, method);
    return true;
  }
  res.setHeader("Cache-Control", "no-store");
  try {
    let result: unknown;
    if (action === "inventory") result = await llmInventory(auth.cfg);
    else {
      const body = await readJsonBodyOrError(req, res, 20000);
      if (res.writableEnded) return true;
      if (action === "readiness") {
        const input = readiness.parse(body);
        result = await Promise.all(
          input.connections.map(async (c) => {
            try {
              await resolveLlmConnection(auth.cfg, c.id, c.model, c.version);
              return { id: c.id, version: c.version, ready: true };
            } catch (error) {
              return {
                id: c.id,
                version: c.version,
                ready: false,
                errorCode:
                  error instanceof LlmConnectionError ? error.code : "readiness_unavailable",
              };
            }
          }),
        );
      } else if (action === "configure")
        result = await configureLlm(auth.cfg, configure.parse(body));
      else if (action === "rollback") {
        const input = rollback.parse(body);
        result = await rollbackLlm(
          input.connectionId,
          input.targetOperationId,
          input.operationId,
          input.expectedVersion,
        );
      } else if (action === "test") {
        const input = test.parse(body);
        // A replacement verifies each active model; only repeated probes of the same revision/model are throttled.
        const testKey = JSON.stringify([input.connectionId, input.version, input.modelId]);
        for (const [id, at] of lastTest) if (Date.now() - at > 60000) lastTest.delete(id);
        if (
          testsInFlight.size >= 4 ||
          (!lastTest.has(testKey) && lastTest.size >= 1000) ||
          testsInFlight.has(input.connectionId) ||
          Date.now() - (lastTest.get(testKey) ?? 0) < 30000
        ) {
          sendJson(res, 429, { ok: false, error: "test_rate_limited" });
          return true;
        }
        testsInFlight.add(input.connectionId);
        lastTest.set(testKey, Date.now());
        try {
          const selected = await resolveLlmConnection(
            auth.cfg,
            input.connectionId,
            input.modelId,
            input.version,
          );
          const { agentCommandFromIngress } = await import("../commands/agent.js");
          const { createDefaultDeps } = await import("../cli/deps.js");
          const { defaultRuntime } = await import("../runtime.js");
          const nonce = randomUUID();
          const inventory = await llmInventory(auth.cfg);
          const connection = inventory.connections.find((c) => c.id === input.connectionId);
          const supportsImage = inventory.providers
            .find((p) => p.id === connection?.provider)
            ?.models.find((m) => m.id === input.modelId)
            ?.capabilities.includes("image");
          let response: unknown;
          let testErrorCode: ReturnType<typeof classifyManagedLlmError> | undefined;
          try {
            response = await agentCommandFromIngress(
              {
                message: `Return only a JSON object with probe equal to "${nonce}"${supportsImage ? ", and color equal to the solid color shown in the attached image" : ""}. Do not retrieve memory or call tools.`,
                model: selected.model,
                pinnedAuthProfileId: selected.profileId,
                managedProvider: selected.managedProvider,
                disableModelFallback: true,
                allowModelOverride: true,
                toolsAllow: [],
                ...(supportsImage
                  ? {
                      images: [{ type: "image" as const, mimeType: "image/png", data: imageProbe }],
                    }
                  : {}),
                deliver: false,
                sessionKey: `managed-model:probe-test:${randomUUID()}`,
                sessionEffects: "internal",
                timeout: "45",
                abortSignal: AbortSignal.timeout(45000),
              },
              defaultRuntime,
              createDefaultDeps(),
            );
          } catch (error) {
            testErrorCode = classifyManagedLlmError(error);
          }
          if (testErrorCode) result = { valid: false, capabilities: [], errorCode: testErrorCode };
          else {
            const identity = managedLlmResultIdentity(response);
            if (identity.error) {
              result = {
                valid: false,
                capabilities: [],
                errorCode: identity.error,
                ...managedLlmUsage(response),
              };
            } else {
              const payloads = (response as { payloads?: Array<{ text?: string }> }).payloads;
              const text = payloads?.map((p) => p.text ?? "").join("") ?? "";
              let valid = false;
              try {
                const parsed = JSON.parse(text);
                valid =
                  identity.model === selected.model &&
                  parsed.probe === nonce &&
                  (!supportsImage || String(parsed.color).toLowerCase() === "red");
              } catch {
                /* Invalid structured output is a failed test. */
              }
              const capabilities = valid
                ? ["text", "json", ...(supportsImage ? ["image"] : [])]
                : [];
              let toolResponse: unknown;
              let toolErrorCode: ReturnType<typeof classifyManagedLlmError> | undefined;
              if (valid) {
                try {
                  toolResponse = await agentCommandFromIngress(
                    {
                      message: `Call llm_probe once with nonce "${nonce}". Do not call other tools.`,
                      model: selected.model,
                      pinnedAuthProfileId: selected.profileId,
                      managedProvider: selected.managedProvider,
                      disableModelFallback: true,
                      allowModelOverride: true,
                      toolsAllow: ["llm_probe"],
                      clientTools: [
                        {
                          type: "function",
                          function: {
                            name: "llm_probe",
                            description:
                              "Harmless capability probe; returns no private information.",
                            parameters: {
                              type: "object",
                              properties: { nonce: { type: "string" } },
                              required: ["nonce"],
                              additionalProperties: false,
                            },
                          },
                        },
                      ],
                      deliver: false,
                      sessionKey: `managed-model:probe-tool-test:${randomUUID()}`,
                      sessionEffects: "internal",
                      timeout: "25",
                      abortSignal: AbortSignal.timeout(25000),
                    },
                    defaultRuntime,
                    createDefaultDeps(),
                  );
                  const toolIdentity = managedLlmResultIdentity(toolResponse);
                  if (toolIdentity.error) {
                    toolErrorCode = toolIdentity.error;
                  } else {
                    const pending = (
                      toolResponse as {
                        meta?: { pendingToolCalls?: Array<{ name: string; arguments: string }> };
                      }
                    ).meta?.pendingToolCalls;
                    if (
                      toolIdentity.model === selected.model &&
                      pending?.some((call) => {
                        try {
                          return (
                            call.name === "llm_probe" && JSON.parse(call.arguments).nonce === nonce
                          );
                        } catch {
                          return false;
                        }
                      })
                    )
                      capabilities.push("tools");
                  }
                } catch (error) {
                  toolErrorCode = classifyManagedLlmError(error);
                }
              }
              result = toolErrorCode
                ? {
                    valid: false,
                    capabilities: [],
                    errorCode: toolErrorCode,
                    ...combineManagedLlmUsage(response, toolResponse),
                  }
                : { valid, capabilities, ...managedLlmUsage(response) };
            }
          }
        } finally {
          testsInFlight.delete(input.connectionId);
          if (lastTest.size > 1000)
            for (const [id, at] of lastTest) if (Date.now() - at > 60000) lastTest.delete(id);
        }
      } else {
        sendJson(res, 404, { ok: false, error: "unsupported_operation" });
        return true;
      }
    }
    sendJson(res, 200, { ok: true, result });
  } catch {
    // Do not serialize exceptions: provider errors and schema errors can contain secrets.
    sendJson(res, 400, { ok: false, error: "llm_operation_failed" });
  }
  return true;
}
