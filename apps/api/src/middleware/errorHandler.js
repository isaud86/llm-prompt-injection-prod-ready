const ApiError = require("../errors/ApiError");
const config = require("../config");

/**
 * Central safe error handler (brief §16/§43). Guarantees:
 *  - stack traces and internal messages are NEVER sent to clients;
 *  - full detail is logged server-side (structured JSON → CloudWatch in prod);
 *  - body-parser errors (malformed JSON / oversized payload) map to 400;
 *  - the response is always `{ error: { code, message, requestId } }`
 *    (plus safe `details` for INVALID_REQUEST).
 */
// eslint-disable-next-line no-unused-vars
module.exports = function errorHandler(err, req, res, next) {
  const requestId = req.requestId;

  let apiErr;
  if (err instanceof ApiError) {
    apiErr = err;
  } else if (err && (err.type === "entity.parse.failed" || err instanceof SyntaxError)) {
    apiErr = new ApiError("INVALID_REQUEST", { cause: err, internalMessage: "Malformed request body" });
  } else if (err && err.type === "entity.too.large") {
    apiErr = new ApiError("INVALID_REQUEST", { cause: err, internalMessage: "Request body too large" });
  } else {
    apiErr = new ApiError("INTERNAL_ERROR", { cause: err });
  }

  // Server-side structured log — full detail, never returned to the client.
  try {
    console.error(
      JSON.stringify({
        level: "error",
        ts: new Date().toISOString(),
        service: "api",
        event: "request_error",
        requestId,
        code: apiErr.code,
        httpStatus: apiErr.httpStatus,
        internalMessage: apiErr.message,
        // Stack is logged (server-side) but only in non-production verbosity to
        // keep prod logs lean; it is never in the HTTP response.
        stack: !config.isProd ? (apiErr.cause && apiErr.cause.stack) || apiErr.stack : undefined,
      }),
    );
  } catch {
    /* logging must never throw */
  }

  const body = { error: { code: apiErr.code, message: apiErr.publicMessage, requestId } };
  if (apiErr.code === "INVALID_REQUEST" && apiErr.details) {
    body.error.details = apiErr.details;
  }
  res.status(apiErr.httpStatus).json(body);
};
