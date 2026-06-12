/**
 * Routes Codex app-server plugin approval prompts through OpenClaw's gateway
 * approval tool and maps gateway decisions back to Codex outcomes.
 */
import { callGatewayTool } from "openclaw/plugin-sdk/agent-harness-runtime";
import { resolveCodexGatewayTimeoutWithGraceMs } from "./attempt-timeouts.js";
import { isJsonObject, type JsonObject, type JsonValue } from "./protocol.js";

const DEFAULT_CODEX_APPROVAL_TIMEOUT_MS = 120_000;
const MAX_PLUGIN_APPROVAL_TITLE_LENGTH = 80;
const MAX_PLUGIN_APPROVAL_DESCRIPTION_LENGTH = 256;

type ExecApprovalDecision = "allow-once" | "allow-always" | "deny";

/** Minimal runtime context needed to route a plugin approval request. */
export type PluginApprovalRunContext = {
  agentId?: string;
  sessionKey?: string;
  messageChannel?: string;
  messageProvider?: string;
  currentChannelId?: string;
  agentAccountId?: string;
  currentThreadTs?: string;
};

/** Normalized Codex app-server approval outcome after a gateway decision. */
export type AppServerApprovalOutcome =
  | "approved-once"
  | "approved-session"
  | "denied"
  | "unavailable"
  | "cancelled";

type ApprovalRequestResult = {
  id?: string;
  decision?: ExecApprovalDecision | null;
};

type ApprovalWaitResult = {
  id?: string;
  decision?: ExecApprovalDecision | null;
};

/** Starts a two-phase plugin approval request through the OpenClaw gateway. */
export async function requestPluginApproval(params: {
  paramsForRun: PluginApprovalRunContext;
  title: string;
  description: string;
  severity: "info" | "warning";
  toolName: string;
  toolCallId?: string;
}): Promise<ApprovalRequestResult | undefined> {
  const timeoutMs = DEFAULT_CODEX_APPROVAL_TIMEOUT_MS;
  return callGatewayTool(
    "plugin.approval.request",
    { timeoutMs: resolveCodexGatewayTimeoutWithGraceMs(timeoutMs) },
    {
      pluginId: "openclaw-codex-app-server",
      title: truncateForGateway(params.title, MAX_PLUGIN_APPROVAL_TITLE_LENGTH),
      description: truncateForGateway(params.description, MAX_PLUGIN_APPROVAL_DESCRIPTION_LENGTH),
      severity: params.severity,
      toolName: params.toolName,
      toolCallId: params.toolCallId,
      agentId: params.paramsForRun.agentId,
      sessionKey: params.paramsForRun.sessionKey,
      turnSourceChannel: params.paramsForRun.messageChannel ?? params.paramsForRun.messageProvider,
      turnSourceTo: params.paramsForRun.currentChannelId,
      turnSourceAccountId: params.paramsForRun.agentAccountId,
      turnSourceThreadId: params.paramsForRun.currentThreadTs,
      timeoutMs,
      twoPhase: true,
    },
    { expectFinal: false },
  ) as Promise<ApprovalRequestResult | undefined>;
}

/** Detects the gateway's explicit null-decision marker for unavailable approvals. */
export function approvalRequestExplicitlyUnavailable(result: unknown): boolean {
  if (result === null || result === undefined || typeof result !== "object") {
    return false;
  }
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(result, "decision");
  } catch {
    return false;
  }
  return descriptor !== undefined && "value" in descriptor && descriptor.value === null;
}

/** Waits for the gateway's final approval decision, respecting turn aborts. */
export async function waitForPluginApprovalDecision(params: {
  approvalId: string;
  signal?: AbortSignal;
}): Promise<ExecApprovalDecision | null | undefined> {
  const timeoutMs = DEFAULT_CODEX_APPROVAL_TIMEOUT_MS;
  const waitPromise: Promise<ApprovalWaitResult | undefined> = callGatewayTool(
    "plugin.approval.waitDecision",
    { timeoutMs: resolveCodexGatewayTimeoutWithGraceMs(timeoutMs) },
    { id: params.approvalId },
  );
  if (!params.signal) {
    return (await waitPromise)?.decision;
  }
  let onAbort: (() => void) | undefined;
  const abortPromise = new Promise<never>((_, reject) => {
    if (params.signal!.aborted) {
      reject(toLintErrorObject(params.signal!.reason, "Non-Error rejection"));
      return;
    }
    onAbort = () => reject(toLintErrorObject(params.signal!.reason, "Non-Error rejection"));
    params.signal!.addEventListener("abort", onAbort, { once: true });
  });
  try {
    return (await Promise.race([waitPromise, abortPromise]))?.decision;
  } finally {
    if (onAbort) {
      params.signal.removeEventListener("abort", onAbort);
    }
  }
}

/** Converts a gateway exec approval decision into the app-server approval outcome enum. */
export function mapExecDecisionToOutcome(
  decision: ExecApprovalDecision | null | undefined,
): AppServerApprovalOutcome {
  if (decision === "allow-once") {
    return "approved-once";
  }
  if (decision === "allow-always") {
    return "approved-session";
  }
  if (decision === null || decision === undefined) {
    return "unavailable";
  }
  return "denied";
}

/** Bound-conversation Codex app-server approval request methods handled by routeCodexBoundApproval. */
export type CodexBoundApprovalMethod =
  | "item/commandExecution/requestApproval"
  | "item/fileChange/requestApproval"
  | "item/permissions/requestApproval";

/**
 * Routes a Codex app-server approval request from a bound conversation
 * through OpenClaw's existing plugin approval UX and maps the gateway
 * decision back to a Codex-shaped response.
 *
 * This replaces the bound-conversation auto-decline that previously
 * forced users onto the Codex harness or `/acp spawn codex`. The
 * approval still fails closed if the OpenClaw approval route is
 * unavailable, the gateway returns no decision, or the user denies.
 *
 * Decisions map as follows (per Codex
 * `codex-rs/protocol/src/protocol.rs:3678-3728`):
 *
 * - `allow-once` → `decision: "approved"` (command/file) or
 *   `permissions: {}, scope: "turn"` (permissions)
 * - `allow-always` → `decision: "approved_for_session"` or
 *   `permissions: ..., scope: "session"`
 * - `deny` → `decision: "denied"` or `permissions: {}, scope: "turn"`
 * - timeout / unavailable / cancel → `decision: "timed_out"` or
 *   `permissions: {}, scope: "turn"`
 *
 * Codex wire contract (verified in `codex-rs/app-server-protocol/src/protocol/common.rs:1336,1343,1361`):
 *
 * - `item/commandExecution/requestApproval` → `ExecApprovalRequestEvent`
 *   (callId, approvalId?, turnId, command, cwd, parsedCmd, ...).
 *   Response: `{ decision: ReviewDecision }`.
 * - `item/fileChange/requestApproval` → `ApplyPatchApprovalRequestEvent`
 *   (callId, turnId, changes, grantRoot?, reason?). Response:
 *   `{ decision: ReviewDecision }`.
 * - `item/permissions/requestApproval` → `ElicitationRequestEvent`
 *   (turnId?, serverName, id, request: { kind, ... }). Response:
 *   `{ permissions, scope: "turn"|"session", strictAutoReview? }`.
 */
export async function routeCodexBoundApproval(params: {
  method: CodexBoundApprovalMethod;
  requestParams: JsonValue | undefined;
  paramsForRun: PluginApprovalRunContext;
  signal?: AbortSignal;
}): Promise<JsonValue | undefined> {
  const requestParams = isJsonObject(params.requestParams) ? params.requestParams : undefined;
  const callId = readString(requestParams, "callId");
  const approvalId = readString(requestParams, "approvalId");
  const command = readStringArray(requestParams, "command");
  const cwd = readString(requestParams, "cwd");
  const reason = readString(requestParams, "reason");
  const isPermissions = params.method === "item/permissions/requestApproval";

  const stableId = buildBoundApprovalId({
    method: params.method,
    callId,
    approvalId,
  });

  const title = buildBoundApprovalTitle({
    method: params.method,
    command,
    cwd,
  });

  const description = buildBoundApprovalDescription({
    method: params.method,
    command,
    cwd,
    reason,
  });

  const toolName =
    params.method === "item/commandExecution/requestApproval"
      ? "codex.command_execution"
      : params.method === "item/fileChange/requestApproval"
        ? "codex.file_change"
        : "codex.permissions";

  const requestResult = await requestPluginApproval({
    paramsForRun: params.paramsForRun,
    title,
    description,
    severity: "warning",
    toolName,
    toolCallId: stableId,
  });
  const approvalIdOut = requestResult?.id;
  if (!approvalIdOut) {
    return buildBoundApprovalResponse(params.method, "denied");
  }

  let decision: ExecApprovalDecision | null | undefined;
  try {
    decision = await waitForPluginApprovalDecision({
      approvalId: approvalIdOut,
      signal: params.signal,
    });
  } catch {
    decision = params.signal?.aborted ? null : "deny";
  }

  if (approvalRequestExplicitlyUnavailable(requestResult)) {
    decision = null;
  }

  if (isPermissions) {
    if (decision === "allow-always") {
      return { permissions: {}, scope: "session" };
    }
    return { permissions: {}, scope: "turn" };
  }

  if (decision === "allow-once") {
    return { decision: "approved" };
  }
  if (decision === "allow-always") {
    return { decision: "approved_for_session" };
  }
  if (decision === null || decision === undefined) {
    return { decision: "timed_out" };
  }
  return { decision: "denied" };
}

function buildBoundApprovalId(params: {
  method: CodexBoundApprovalMethod;
  callId: string | undefined;
  approvalId: string | undefined;
}): string {
  const kind =
    params.method === "item/commandExecution/requestApproval"
      ? "exec"
      : params.method === "item/fileChange/requestApproval"
        ? "patch"
        : "permissions";
  const idSegment = params.approvalId ?? params.callId ?? "unknown";
  return `${kind}:${idSegment}`;
}

function buildBoundApprovalTitle(params: {
  method: CodexBoundApprovalMethod;
  command: string[] | undefined;
  cwd: string | undefined;
}): string {
  if (params.method === "item/commandExecution/requestApproval") {
    return "Codex wants to run a command";
  }
  if (params.method === "item/fileChange/requestApproval") {
    return "Codex wants to apply file changes";
  }
  return "Codex wants elevated permissions";
}

function buildBoundApprovalDescription(params: {
  method: CodexBoundApprovalMethod;
  command: string[] | undefined;
  cwd: string | undefined;
  reason: string | undefined;
}): string {
  if (params.method === "item/commandExecution/requestApproval") {
    const cmd =
      params.command && params.command.length > 0 ? params.command.join(" ") : "(no command)";
    return params.cwd ? `Run: ${cmd}\nCwd: ${params.cwd}` : `Run: ${cmd}`;
  }
  if (params.method === "item/fileChange/requestApproval") {
    return params.reason ? `Reason: ${params.reason}` : "Codex wants to apply file changes.";
  }
  return params.reason
    ? `Reason: ${params.reason}`
    : "Codex wants elevated permissions for the current turn.";
}

function buildBoundApprovalResponse(
  method: CodexBoundApprovalMethod,
  decision: "approved" | "approved_for_session" | "denied" | "timed_out",
): JsonValue {
  if (method === "item/permissions/requestApproval") {
    return { permissions: {}, scope: decision === "approved_for_session" ? "session" : "turn" };
  }
  return { decision };
}

function readString(obj: JsonObject | undefined, key: string): string | undefined {
  if (!obj) {
    return undefined;
  }
  const value = obj[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readStringArray(obj: JsonObject | undefined, key: string): string[] | undefined {
  if (!obj) {
    return undefined;
  }
  const value = obj[key];
  if (!Array.isArray(value)) {
    return undefined;
  }
  return value.every((entry): entry is string => typeof entry === "string" && entry.length > 0)
    ? value
    : undefined;
}

function truncateForGateway(value: string, maxLength: number): string {
  return value.length <= maxLength ? value : `${value.slice(0, Math.max(0, maxLength - 3))}...`;
}

function toLintErrorObject(value: unknown, fallbackMessage: string): Error {
  if (value instanceof Error) {
    return value;
  }
  if (typeof value === "string") {
    return new Error(value);
  }
  const error = new Error(fallbackMessage, { cause: value });
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    Object.assign(error, value);
  }
  return error;
}
