# oidc-auth-fastapi

Reusable BFF OIDC auth for FastAPI apps (Authlib code-exchange + Starlette
HttpOnly session cookie). DB-agnostic: you supply `find_or_create_user(claims)
-> user_id`. Config-gated — when `OIDC_*` env is unset, `current_user` resolves a
fixed dev-owner (`user_id=1`) so local dev and tests run with no IdP.

## Usage
    from oidc_auth import OIDCAuth, OidcConfig, resolve_current_user, SessionUser
    oidc = OIDCAuth(app, find_or_create_user=cb)   # mounts /auth/login|callback|logout|me
    # gate routes with Depends(oidc.current_user), or build your own dependency
    # via resolve_current_user(request, OidcConfig.from_env()).

## Env
OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_REDIRECT_URI,
OIDC_SCOPES (default "openid profile email groups"), plus SESSION_SECRET for the
host app's SessionMiddleware.
