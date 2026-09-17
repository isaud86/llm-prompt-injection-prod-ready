const ApiError = require("../errors/ApiError");

/**
 * Zod validation middleware factory (brief API SECURITY). Validates `req[part]`
 * against `schema`. On failure it raises INVALID_REQUEST with SAFE structured
 * issues (field path + message only — never echoes the raw payload or internal
 * detail). On success it replaces `req[part]` with the parsed, sanitized data so
 * unknown keys are stripped (mass-assignment defense; schemas use `.strict()`).
 */
function validate(schema, part = "body") {
  return (req, _res, next) => {
    const result = schema.safeParse(req[part]);
    if (!result.success) {
      const issues = result.error.issues.map((i) => ({
        path: Array.isArray(i.path) ? i.path.join(".") : String(i.path),
        message: i.message,
      }));
      return next(new ApiError("INVALID_REQUEST", { details: { issues } }));
    }
    req[part] = result.data;
    return next();
  };
}

module.exports = { validate };
