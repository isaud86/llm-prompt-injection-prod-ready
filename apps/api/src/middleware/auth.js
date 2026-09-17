/**
 * Authentication boundary (brief: "No authentication yet ... design middleware
 * boundaries so Cognito authentication can be inserted cleanly later" — Phase 3).
 *
 * Today this attaches an anonymous principal. In Phase 3, the body of this
 * function is replaced by Cognito JWT verification (validate signature via cached
 * JWKS, check expiry/audience, load role from the DB) WITHOUT changing its
 * contract: on success it sets `req.auth = { userId, roles, authenticated:true }`;
 * on a required-but-missing/invalid token it calls `next(new ApiError('AUTH_REQUIRED'))`.
 * Routes and services depend only on `req.auth`, so no downstream code changes
 * when real auth lands.
 */
module.exports = function attachAuth(req, _res, next) {
  req.auth = { userId: null, roles: ["anonymous"], authenticated: false };
  next();
};
