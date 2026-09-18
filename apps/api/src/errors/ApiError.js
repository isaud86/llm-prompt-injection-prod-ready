/**
 * Typed error catalogue (brief §16/§43). Each code maps to an HTTP status and a
 * SAFE, human-readable public message. Internal detail (cause, internalMessage)
 * is kept on the instance for server-side logging ONLY and is never serialized
 * to clients.
 */
const CATALOG = {
  INVALID_REQUEST: { httpStatus: 400, message: "The request was invalid." },
  AUTH_REQUIRED: { httpStatus: 401, message: "Authentication is required." },
  RATE_LIMITED: { httpStatus: 429, message: "Too many requests. Please slow down and try again." },
  SECURITY_BLOCKED: { httpStatus: 403, message: "Your request could not be processed." },
  MODEL_UNAVAILABLE: { httpStatus: 503, message: "The AI service is temporarily unavailable." },
  INFERENCE_TIMEOUT: { httpStatus: 504, message: "The request timed out. Please try again." },
  SERVICE_UNAVAILABLE: { httpStatus: 503, message: "The service is temporarily unavailable." },
  INTERNAL_ERROR: { httpStatus: 500, message: "An unexpected error occurred." },
};

class ApiError extends Error {
  /**
   * @param {keyof typeof CATALOG} code
   * @param {{ internalMessage?: string, httpStatus?: number, details?: object, cause?: Error }} [opts]
   */
  constructor(code, opts = {}) {
    const known = Object.prototype.hasOwnProperty.call(CATALOG, code);
    const entry = known ? CATALOG[code] : CATALOG.INTERNAL_ERROR;
    super(opts.internalMessage || entry.message);
    this.name = "ApiError";
    this.code = known ? code : "INTERNAL_ERROR";
    this.httpStatus = opts.httpStatus || entry.httpStatus;
    this.publicMessage = entry.message;
    // `details` must be SAFE (e.g. Zod issue paths/messages) — only ever attached
    // for INVALID_REQUEST and validated before exposure.
    this.details = opts.details;
    this.cause = opts.cause;
  }
}

ApiError.CATALOG = CATALOG;
module.exports = ApiError;
