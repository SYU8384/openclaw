// Codex tests cover plugin approval round-trip helpers.
import { callGatewayTool } from "openclaw/plugin-sdk/agent-harness-runtime";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  approvalRequestExplicitlyUnavailable,
  requestPluginApproval,
  routeCodexBoundApproval,
  waitForPluginApprovalDecision,
} from "./plugin-approval-roundtrip.js";

vi.mock("openclaw/plugin-sdk/agent-harness-runtime", async (importOriginal) => ({
  ...(await importOriginal<typeof import("openclaw/plugin-sdk/agent-harness-runtime")>()),
  callGatewayTool: vi.fn(),
}));

const mockCallGatewayTool = vi.mocked(callGatewayTool);

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Expected ${label}`);
  }
  return value as Record<string, unknown>;
}

function gatewayCallAt(callIndex = 0) {
  const call = mockCallGatewayTool.mock.calls[callIndex];
  if (!call) {
    throw new Error(`Expected gateway call ${callIndex + 1}`);
  }
  return call;
}

function gatewayRequestPayload(callIndex = 0) {
  return requireRecord(gatewayCallAt(callIndex)[2], `gateway request payload ${callIndex + 1}`);
}

function createRunContext() {
  return {
    agentId: "main",
    sessionKey: "agent:main:session-1",
    messageChannel: "telegram",
    currentChannelId: "chat-1",
    agentAccountId: "default",
    currentThreadTs: "thread-ts",
  };
}

describe("Codex plugin approval round-trip", () => {
  beforeEach(() => {
    mockCallGatewayTool.mockReset();
  });

  describe("requestPluginApproval", () => {
    it("requests a two-phase plugin approval through the gateway", async () => {
      mockCallGatewayTool.mockResolvedValueOnce({ id: "approval-1" });
      const result = await requestPluginApproval({
        paramsForRun: createRunContext(),
        title: "Test title",
        description: "Test description",
        severity: "warning",
        toolName: "codex.command_execution",
        toolCallId: "exec:call-1",
      });
      expect(result).toEqual({ id: "approval-1" });
      expect(gatewayCallAt(0)[0]).toBe("plugin.approval.request");
      const payload = gatewayRequestPayload(0);
      expect(payload.pluginId).toBe("openclaw-codex-app-server");
      expect(payload.title).toBe("Test title");
      expect(payload.description).toBe("Test description");
      expect(payload.severity).toBe("warning");
      expect(payload.toolName).toBe("codex.command_execution");
      expect(payload.toolCallId).toBe("exec:call-1");
      expect(payload.agentId).toBe("main");
      expect(payload.sessionKey).toBe("agent:main:session-1");
      expect(payload.turnSourceChannel).toBe("telegram");
      expect(payload.turnSourceTo).toBe("chat-1");
      expect(payload.turnSourceAccountId).toBe("default");
      expect(payload.turnSourceThreadId).toBe("thread-ts");
      expect(payload.twoPhase).toBe(true);
    });
  });

  describe("waitForPluginApprovalDecision", () => {
    it("returns the gateway decision", async () => {
      mockCallGatewayTool.mockResolvedValueOnce({ id: "approval-1", decision: "allow-once" });
      const decision = await waitForPluginApprovalDecision({ approvalId: "approval-1" });
      expect(decision).toBe("allow-once");
      expect(gatewayCallAt(0)[0]).toBe("plugin.approval.waitDecision");
    });

    it("returns undefined when the gateway returns no decision", async () => {
      mockCallGatewayTool.mockResolvedValueOnce({ id: "approval-1" });
      const decision = await waitForPluginApprovalDecision({ approvalId: "approval-1" });
      expect(decision).toBeUndefined();
    });
  });

  describe("approvalRequestExplicitlyUnavailable", () => {
    it("detects an explicit null decision", () => {
      expect(approvalRequestExplicitlyUnavailable({ id: "approval-1", decision: null })).toBe(true);
    });

    it("returns false for a real decision", () => {
      expect(
        approvalRequestExplicitlyUnavailable({ id: "approval-1", decision: "allow-once" }),
      ).toBe(false);
    });
  });

  describe("routeCodexBoundApproval", () => {
    it("approves a command execution request", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "allow-once" });
      const result = await routeCodexBoundApproval({
        method: "item/commandExecution/requestApproval",
        requestParams: { callId: "call-1", command: ["ls", "-la"], cwd: "/workspace" },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("approved");
    });

    it("approves a command execution for the session", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "allow-always" });
      const result = await routeCodexBoundApproval({
        method: "item/commandExecution/requestApproval",
        requestParams: { callId: "call-1", command: ["git", "push"] },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("approved_for_session");
    });

    it("denies a command execution request", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "deny" });
      const result = await routeCodexBoundApproval({
        method: "item/commandExecution/requestApproval",
        requestParams: { callId: "call-1", command: ["rm", "-rf", "/"] },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("denied");
    });

    it("times out when the gateway decision is unavailable", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1", decision: null })
        .mockResolvedValueOnce({ id: "approval-1" });
      const result = await routeCodexBoundApproval({
        method: "item/commandExecution/requestApproval",
        requestParams: { callId: "call-1" },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("timed_out");
    });

    it("denies when the approval route returns no id", async () => {
      mockCallGatewayTool.mockResolvedValueOnce({});
      const result = await routeCodexBoundApproval({
        method: "item/commandExecution/requestApproval",
        requestParams: { callId: "call-1" },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("denied");
    });

    it("approves file changes for the current turn", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "allow-once" });
      const result = await routeCodexBoundApproval({
        method: "item/fileChange/requestApproval",
        requestParams: { callId: "call-1", reason: "Update README" },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("approved");
    });

    it("approves file changes for the session", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "allow-always" });
      const result = await routeCodexBoundApproval({
        method: "item/fileChange/requestApproval",
        requestParams: { callId: "call-1" },
        paramsForRun: createRunContext(),
      });
      expect(requireRecord(result, "result").decision).toBe("approved_for_session");
    });

    it("approves permissions for the current turn", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "allow-once" });
      const result = await routeCodexBoundApproval({
        method: "item/permissions/requestApproval",
        requestParams: { serverName: "mcp", id: "tool-1" },
        paramsForRun: createRunContext(),
      });
      const record = requireRecord(result, "result");
      expect(record.permissions).toEqual({});
      expect(record.scope).toBe("turn");
    });

    it("approves permissions for the session", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1" })
        .mockResolvedValueOnce({ id: "approval-1", decision: "allow-always" });
      const result = await routeCodexBoundApproval({
        method: "item/permissions/requestApproval",
        requestParams: { serverName: "mcp", id: "tool-1" },
        paramsForRun: createRunContext(),
      });
      const record = requireRecord(result, "result");
      expect(record.permissions).toEqual({});
      expect(record.scope).toBe("session");
    });

    it("denies permissions when the gateway decision is unavailable", async () => {
      mockCallGatewayTool
        .mockResolvedValueOnce({ id: "approval-1", decision: null })
        .mockResolvedValueOnce({ id: "approval-1" });
      const result = await routeCodexBoundApproval({
        method: "item/permissions/requestApproval",
        requestParams: { serverName: "mcp", id: "tool-1" },
        paramsForRun: createRunContext(),
      });
      const record = requireRecord(result, "result");
      expect(record.permissions).toEqual({});
      expect(record.scope).toBe("turn");
    });
  });
});
