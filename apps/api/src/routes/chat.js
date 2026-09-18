const express = require("express");
const { z } = require("zod");
const { validate } = require("../middleware/validate");
const { buildRequestContext } = require("../context/requestContext");
const { handleChat } = require("../services/chatService");
const config = require("../config");

const router = express.Router();

// Request schema (brief API SECURITY). `.strict()` rejects unknown keys
// (mass-assignment defense). Client-supplied ids must be UUIDs or are ignored.
const chatSchema = z
  .object({
    message: z.string().min(1).max(config.maxMessageLength),
    conversationId: z.string().uuid().optional(),
    sessionId: z.string().uuid().optional(),
    // C1–C5 preset is accepted but only honored for researchers (see chatService).
    preset: z.enum(["c1", "c2", "c3", "c4", "c5"]).optional(),
  })
  .strict();

router.post("/v1/chat", validate(chatSchema), async (req, res, next) => {
  try {
    const ctx = buildRequestContext({
      requestId: req.requestId,
      auth: req.auth,
      conversationId: req.body.conversationId,
      sessionId: req.body.sessionId,
    });
    const dto = await handleChat({ message: req.body.message, preset: req.body.preset }, ctx);
    res.status(200).json(dto);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
