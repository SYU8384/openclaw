/** Only trusted runtime failures feed this classification, never model reply text. */
export function classifyManagedLlmError(
  error: unknown,
):
  | "authentication_failed"
  | "insufficient_balance"
  | "rate_limited"
  | "unreachable"
  | "invalid_output" {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  if (
    /\b402\b|insufficient[ _-]balance|insufficient[ _-]quota|billing[ _-](error|limit|hard_limit)|credit balance.*(low|exhausted)/i.test(
      message,
    )
  )
    return "insufficient_balance";
  if (
    /No API key|credential[ _](unavailable|missing)|invalid.{0,12}(api.?key|credential)|unauthorized|authentication|\b401\b|\b403\b/i.test(
      message,
    )
  )
    return "authentication_failed";
  if (/rate.?limit|\b429\b/i.test(message)) return "rate_limited";
  return "unreachable";
}
export function managedLlmResultIdentity(result: unknown): {
  model?: string;
  error?:
    | "authentication_failed"
    | "insufficient_balance"
    | "rate_limited"
    | "unreachable"
    | "invalid_output";
} {
  const meta = (
    result as {
      meta?: {
        error?: { message?: string };
        aborted?: boolean;
        agentMeta?: { provider?: string; model?: string };
      };
    } | null
  )?.meta;
  if (meta?.error || meta?.aborted) return { error: classifyManagedLlmError(meta.error?.message) };
  const provider = meta?.agentMeta?.provider,
    model = meta?.agentMeta?.model;
  if (!provider || !model) return { error: "invalid_output" };
  return { model: `${provider}/${model}` };
}
