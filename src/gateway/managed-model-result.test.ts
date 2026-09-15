import { expect, it } from "vitest";
import { classifyManagedLlmError, managedLlmResultIdentity } from "./managed-model-result.js";
it("does not interpret reply prose as an operational error", () => {
  expect(
    managedLlmResultIdentity({
      payloads: [{ text: "401 authentication failure" }],
      meta: { agentMeta: { provider: "provider", model: "model" } },
    }),
  ).toEqual({ model: "provider/model" });
});
it("requires actual runtime model identity", () => {
  expect(managedLlmResultIdentity({ payloads: [{ text: '{"ok":true}' }] })).toEqual({
    error: "invalid_output",
  });
  expect(managedLlmResultIdentity({ meta: { aborted: true } })).toEqual({ error: "unreachable" });
});
it("normalizes trusted failures without exposing their content", () => {
  expect(classifyManagedLlmError(new Error("credential_unavailable"))).toBe(
    "authentication_failed",
  );
  expect(classifyManagedLlmError(new Error("HTTP 429"))).toBe("rate_limited");
  expect(classifyManagedLlmError(new Error("private diagnostic"))).toBe("unreachable");
});

it("preserves billing failures across thrown and terminal managed results", () => {
  expect(classifyManagedLlmError(new Error("402 Insufficient Balance"))).toBe(
    "insufficient_balance",
  );
  expect(managedLlmResultIdentity({ meta: { error: { message: "billing_error" } } })).toEqual({
    error: "insufficient_balance",
  });
});
