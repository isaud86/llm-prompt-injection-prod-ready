const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const config = require("./config");
const requestId = require("./middleware/requestId");
const attachAuth = require("./middleware/auth");
const errorHandler = require("./middleware/errorHandler");
const healthRoutes = require("./routes/health");
const chatRoutes = require("./routes/chat");
const ApiError = require("./errors/ApiError");

/**
 * Assemble the Express app (brief Phase 5). Exposed as a factory so tests can
 * exercise it with supertest without binding a port.
 *
 * Middleware order: security headers -> strict CORS -> request id -> body parse
 * (size-limited) -> auth boundary -> routes -> 404 -> safe error handler.
 */
function createApp() {
  const app = express();
  app.disable("x-powered-by");

  // Security headers (Helmet) with a strict CSP appropriate for a JSON API.
  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
        },
      },
      // HSTS is meaningful only behind TLS; enable in production (ALB terminates TLS).
      hsts: config.isProd ? undefined : false,
    }),
  );

  // Strict CORS: only explicitly allowlisted origins; requests with no Origin
  // (same-origin, curl, server-to-server) are allowed. Credentials off.
  app.use(
    cors({
      origin: (origin, cb) => {
        if (!origin) return cb(null, true);
        if (config.corsOrigins.includes(origin)) return cb(null, true);
        return cb(
          new ApiError("INVALID_REQUEST", {
            internalMessage: `CORS origin not allowed: ${origin}`,
          }),
        );
      },
      methods: ["GET", "POST"],
      maxAge: 600,
    }),
  );

  app.use(requestId);
  app.use(express.json({ limit: config.bodyLimit }));
  app.use(attachAuth);

  // Health endpoints at root; versioned API under /api.
  app.use(healthRoutes);
  app.use("/api", chatRoutes); // -> POST /api/v1/chat

  // Unknown route -> safe 400 (no route disclosure beyond the generic message).
  app.use((req, _res, next) =>
    next(new ApiError("INVALID_REQUEST", { internalMessage: `No route: ${req.method} ${req.path}` })),
  );

  app.use(errorHandler);
  return app;
}

module.exports = { createApp };
