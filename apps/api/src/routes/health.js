const express = require("express");
const { checkReadiness } = require("../services/readiness");

const router = express.Router();

/**
 * Liveness (brief §26). Confirms the process is running. No dependency probing,
 * no sensitive detail.
 */
router.get("/healthz", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

/**
 * Readiness (brief §26). Confirms dependencies required to serve traffic. The
 * PUBLIC response is intentionally minimal — { status: "ready" | "not_ready" }.
 * Detailed per-check results are logged server-side only (no infra disclosure).
 */
router.get("/readyz", async (req, res, next) => {
  try {
    const { ready, checks } = await checkReadiness();
    try {
      console.log(
        JSON.stringify({
          level: "info",
          ts: new Date().toISOString(),
          service: "api",
          event: "readyz",
          requestId: req.requestId,
          ready,
          checks,
        }),
      );
    } catch {
      /* logging must never throw */
    }
    res.status(ready ? 200 : 503).json({ status: ready ? "ready" : "not_ready" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
