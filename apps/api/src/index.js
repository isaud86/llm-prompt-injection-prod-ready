const { createApp } = require("./app");
const config = require("./config");

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
