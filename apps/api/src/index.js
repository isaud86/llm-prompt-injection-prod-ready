const { createApp } = require("./app");
const config = require("./config");
const pipeline = require("./services/pipeline");
const { assertStartupInvariants, FatalConfigurationError } = require("./startupInvariant");

// Refuse to start a production API in a non-production (fail-open) mode.
try {
  assertStartupInvariants({
    nodeEnv: process.env.NODE_ENV,
    appModeName: pipeline.modeName(),
  });
} catch (err) {
  if (err instanceof FatalConfigurationError) {
    console.error(
      JSON.stringify({
        level: "fatal",
        ts: new Date().toISOString(),
        service: "api",
        event: "startup_aborted",
        code: err.code,
        message: err.message,
      }),
    );
    process.exit(1);
  }
  throw err;
}

const app = createApp();

const server = app.listen(config.port, () => {
  console.log(
    JSON.stringify({
      level: "info",
      ts: new Date().toISOString(),
      service: "api",
      event: "api_start",
      port: config.port,
      env: config.env,
    }),
  );
});

// Graceful shutdown so the process can be supervised/restarted cleanly.
for (const sig of ["SIGTERM", "SIGINT"]) {
  process.on(sig, () => {
    console.log(
      JSON.stringify({ level: "info", ts: new Date().toISOString(), service: "api", event: "shutdown", signal: sig }),
    );
    server.close(() => process.exit(0));
  });
}

module.exports = server;
