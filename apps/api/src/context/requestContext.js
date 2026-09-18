const { randomUUID } = require("crypto");

/**
 * Build the per-request context (brief "REQUEST CONTEXT").
 *
 * Fields: requestId, userId (null until Cognito auth — Phase 3), conversationId,
 * sessionId, isResearcher (role gate), and contextId (the isolation key passed to
 * research-core: `${userId|'anon'}:${conversationId}`).
 *
 * Client-supplied conversationId/sessionId are validated as UUIDs upstream (Zod)
 * and never trusted raw. When absent, unguessable UUIDs are generated server-side
 * and returned to the client. IMPORTANT: until Phase 3 auth, conversation
 * isolation relies on the client holding an unguessable id and is NOT an
 * authenticated boundary — see docs/SECURITY.md. Phase 3 replaces 'anon' with the
 * verified Cognito subject with no change to this contract.
 */
function buildRequestContext({ requestId, auth, conversationId, sessionId }) {
  const roles = (auth && Array.isArray(auth.roles) && auth.roles) || [];
  const userId = auth && auth.userId ? auth.userId : null;
  const convo = conversationId || randomUUID();
  const sess = sessionId || randomUUID();
  return {
    requestId,
    userId,
    conversationId: convo,
    sessionId: sess,
    isResearcher: roles.includes("researcher") || roles.includes("admin"),
    contextId: `${userId || "anon"}:${convo}`,
  };
}

module.exports = { buildRequestContext };
