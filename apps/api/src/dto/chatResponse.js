/**
 * Response DTO serializer (brief §42, §15, §16).
 *
 * Maps the internal research-core result to the ONLY fields permitted to leave
 * the system. Everything else is dropped by construction — this function builds a
 * fresh object and never spreads the raw result, so internal fields such as
 * `reasoning`, `threatCategory`, `violationType`, rule `evidence`, `logEntry`,
 * raw command output objects, hidden prompts, and any model `thinking`/
 * chain-of-thought can never leak, even if present on the input.
 */
function toChatDTO(result, ctx, model, latencyMs) {
  const blocked = result && result.status === "VIOLATION";
  const responseText = blocked
    ? result.warningMessage || "Your request could not be processed."
    : (result && (result.output || result.conversationalResponse || result.warningMessage)) || "";

  return {
    requestId: ctx.requestId,
    conversationId: ctx.conversationId,
    status: blocked ? "BLOCKED" : "SAFE",
    response: responseText,
    model,
    latencyMs,
  };
}

module.exports = { toChatDTO };
