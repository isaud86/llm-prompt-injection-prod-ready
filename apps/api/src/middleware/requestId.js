const { randomUUID } = require("crypto");

/**
 * Assign a correlation id to every request (brief §44). An inbound
 * `x-request-id` is honored only if it looks like a safe id (hex/uuid chars,
 * bounded length); otherwise a fresh UUID is generated. The id is echoed on the
 * response and used throughout logs, errors, and the response DTO.
 */
module.exports = function requestId(req, res, next) {
  const inbound = req.headers["x-request-id"];
  const valid =
    typeof inbound === "string" && /^[0-9a-fA-F-]{8,64}$/.test(inbound);
  req.requestId = valid ? inbound : randomUUID();
  res.setHeader("x-request-id", req.requestId);
  next();
};
