const pipeline = require("./pipeline");
const config = require("../config");
const ApiError = require("../errors/ApiError");
const { toChatDTO } = require("../dto/chatResponse");

/**
 * Race a promise against a timeout, rejecting with INFERENCE_TIMEOUT (brief:
 * timeout handling). Always clears the timer.
 */
function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ApiError("INFERENCE_TIMEOUT")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * Run one chat turn through research-core and serialize to the safe DTO.
 *  - isolation: uses ctx.contextId (`${userId|anon}:${conversationId}`);
 *  - C1–C5 preset overrides are applied ONLY for researchers (anon always gets
 *    the full pipeline — clients cannot weaken defenses);
 *  - rate-limit violations become a 429 typed error; other blocks return a
 *    normal 200 DTO with status "BLOCKED";
 *  - any thrown/rejected pipeline error becomes INTERNAL_ERROR (no leak).
 */
async function handleChat({ message, preset }, ctx) {
  const start = Date.now();

  const options = { contextId: ctx.contextId };
  if (ctx.isResearcher && preset && pipeline.PRESETS[preset]) {
    Object.assign(options, pipeline.PRESETS[preset]);
  }

  let result;
  try {
    result = await withTimeout(
      Promise.resolve(pipeline.processInput(message, options)),
      config.requestTimeoutMs,
    );
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError("INTERNAL_ERROR", { cause: err });
  }

  // Production fail-safe: research-core signals inference unavailability with the
  // UNAVAILABLE status (no command executed, no conversation generated). Map it to
  // a safe typed error — never a SAFE/BLOCKED DTO.
  if (result && result.status === "UNAVAILABLE") {
    throw new ApiError("MODEL_UNAVAILABLE");
  }

  if (result && result.status === "VIOLATION" && result.violationType === "rate_limit") {
    throw new ApiError("RATE_LIMITED");
  }

  const latencyMs = Date.now() - start;
  return toChatDTO(result, ctx, pipeline.model(), latencyMs);
}

module.exports = { handleChat };
