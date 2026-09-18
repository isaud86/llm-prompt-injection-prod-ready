const path = require("path");
const { spawnSync, spawn } = require("child_process");
const {
  assertStartupInvariants,
  FatalConfigurationError,
} = require("../src/startupInvariant");

const ENTRY = path.join(__dirname, "..", "src", "index.js");
const ROOT = path.join(__dirname, "..", "..", "..");

describe("startup invariant (pure function)", () => {
  test("NODE_ENV=production + APP_MODE=production → allowed", () => {
    expect(() =>
      assertStartupInvariants({ nodeEnv: "production", appModeName: "production" }),
    ).not.toThrow();
  });

  test("NODE_ENV=production + APP_MODE missing → rejected", () => {
    expect(() =>
      assertStartupInvariants({ nodeEnv: "production", appModeName: undefined }),
    ).toThrow(FatalConfigurationError);
  });

  test("NODE_ENV=production + APP_MODE=research → rejected", () => {
    expect(() =>
      assertStartupInvariants({ nodeEnv: "production", appModeName: "research" }),
    ).toThrow(/APP_MODE=production/);
  });

  test("NODE_ENV=production + APP_MODE=test → rejected", () => {
    expect(() =>
      assertStartupInvariants({ nodeEnv: "production", appModeName: "test" }),
    ).toThrow(FatalConfigurationError);
  });

  test("NODE_ENV=test + APP_MODE=test → allowed", () => {
    expect(() =>
      assertStartupInvariants({ nodeEnv: "test", appModeName: "test" }),
    ).not.toThrow();
  });

  test("research/eval (NODE_ENV unset) + APP_MODE=research → allowed (unchanged)", () => {
    expect(() =>
      assertStartupInvariants({ nodeEnv: undefined, appModeName: "research" }),
    ).not.toThrow();
  });
});

describe("startup invariant (real API process)", () => {
  const childEnv = (overrides, { unsetAppMode = false } = {}) => {
    const e = { ...process.env, ...overrides };
    if (unsetAppMode) delete e.APP_MODE;
    return e;
  };

  const runToExit = (env) =>
    spawnSync("node", [ENTRY], { cwd: ROOT, env, encoding: "utf8", timeout: 20000 });

  test("NODE_ENV=production + APP_MODE unset → process refuses to start (exit 1)", () => {
    const r = runToExit(childEnv({ NODE_ENV: "production", API_PORT: "34811" }, { unsetAppMode: true }));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/FATAL_CONFIGURATION_ERROR/);
    expect(r.stdout || "").not.toMatch(/api_start/);
  });

  test("NODE_ENV=production + APP_MODE=research → process refuses to start (exit 1)", () => {
    const r = runToExit(childEnv({ NODE_ENV: "production", APP_MODE: "research", API_PORT: "34812" }));
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/FATAL_CONFIGURATION_ERROR/);
  });

  test("NODE_ENV=production + APP_MODE=production → process starts", (done) => {
    const port = "34813";
    const child = spawn("node", [ENTRY], {
      cwd: ROOT,
      env: childEnv({ NODE_ENV: "production", APP_MODE: "production", API_PORT: port }),
    });
    let out = "";
    let settled = false;
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      try { child.kill("SIGTERM"); } catch { /* ignore */ }
      fn();
    };
    const timer = setTimeout(() => finish(() => done(new Error("API did not start in time"))), 15000);
    child.stdout.on("data", (d) => {
      out += d.toString();
      if (out.includes("api_start")) {
        clearTimeout(timer);
        finish(() => done());
      }
    });
    child.stderr.on("data", (d) => {
      if (d.toString().includes("FATAL_CONFIGURATION_ERROR")) {
        clearTimeout(timer);
        finish(() => done(new Error("production+production must NOT abort startup")));
      }
    });
  }, 20000);
});
