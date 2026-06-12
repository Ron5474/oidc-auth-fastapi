"""Reusable, DB-agnostic OIDC auth for FastAPI apps (BFF HttpOnly-cookie session).

Knows OIDC + a `find_or_create_user(claims) -> user_id` callback; nothing about
any app's schema. When OIDC env is unconfigured, `current_user` resolves to a
fixed dev-owner so local dev + tests run with no IdP.
"""
import os
from dataclasses import dataclass, field

from fastapi import Depends, FastAPI, HTTPException, Request


@dataclass
class SessionUser:
    user_id: int
    sub: str
    email: str | None = None
    name: str | None = None
    groups: list[str] = field(default_factory=list)


DEV_OWNER = SessionUser(user_id=1, sub="dev-owner", email=None, name="Local Dev", groups=["admins"])


@dataclass
class OidcConfig:
    issuer: str = ""
    client_id: str = ""
    client_secret: str = ""
    redirect_uri: str = ""
    scopes: str = "openid profile email groups"

    @classmethod
    def from_env(cls) -> "OidcConfig":
        return cls(
            issuer=os.environ.get("OIDC_ISSUER", ""),
            client_id=os.environ.get("OIDC_CLIENT_ID", ""),
            client_secret=os.environ.get("OIDC_CLIENT_SECRET", ""),
            redirect_uri=os.environ.get("OIDC_REDIRECT_URI", ""),
            scopes=os.environ.get("OIDC_SCOPES", "openid profile email groups"),
        )

    @property
    def enabled(self) -> bool:
        return bool(self.issuer and self.client_id and self.client_secret)


def resolve_current_user(request, config: "OidcConfig") -> SessionUser:
    if not config.enabled:
        return SessionUser(user_id=DEV_OWNER.user_id, sub=DEV_OWNER.sub,
                           email=DEV_OWNER.email, name=DEV_OWNER.name,
                           groups=list(DEV_OWNER.groups))
    data = request.session.get("user")
    if not data:
        raise HTTPException(status_code=401, detail="not authenticated")
    try:
        return SessionUser(**data)
    except TypeError:
        raise HTTPException(status_code=401, detail="invalid session")


class OIDCAuth:
    def __init__(self, app: FastAPI, find_or_create_user, config: OidcConfig | None = None):
        """find_or_create_user: a SYNCHRONOUS callable claims(dict) -> user_id(int),
        invoked in /auth/callback. Must not be async (its return value is stored
        directly in the session)."""
        self.config = config or OidcConfig.from_env()
        self.find_or_create_user = find_or_create_user
        self._oauth = None
        if self.config.enabled:
            from authlib.integrations.starlette_client import OAuth
            oauth = OAuth()
            oauth.register(
                name="idp",
                server_metadata_url=self.config.issuer.rstrip("/") + "/.well-known/openid-configuration",
                client_id=self.config.client_id,
                client_secret=self.config.client_secret,
                client_kwargs={"scope": self.config.scopes, "code_challenge_method": "S256"},
            )
            self._oauth = oauth
        self._mount(app)

    async def current_user(self, request: Request) -> SessionUser:
        return resolve_current_user(request, self.config)

    def require_group(self, name: str):
        async def dep(request: Request) -> SessionUser:
            user = await self.current_user(request)
            if name not in user.groups:
                raise HTTPException(status_code=403, detail="forbidden")
            return user
        return dep

    def _mount(self, app: FastAPI) -> None:
        from starlette.responses import JSONResponse, RedirectResponse

        @app.get("/auth/login")
        async def login(request: Request):
            if not self.config.enabled:
                raise HTTPException(status_code=404, detail="auth not configured")
            try:
                return await self._oauth.idp.authorize_redirect(request, self.config.redirect_uri)
            except Exception:
                raise HTTPException(status_code=503, detail="identity provider unavailable")

        @app.get("/auth/callback")
        async def callback(request: Request):
            if not self.config.enabled:
                raise HTTPException(status_code=404, detail="auth not configured")
            try:
                token = await self._oauth.idp.authorize_access_token(request)
            except Exception:
                request.session.pop("user", None)
                return RedirectResponse(url="/auth/login", status_code=302)
            claims = token.get("userinfo") or {}
            sub = claims.get("sub")
            if not sub:
                raise HTTPException(status_code=401, detail="invalid token")
            user_id = self.find_or_create_user(claims)
            request.session["user"] = {
                "user_id": user_id, "sub": sub,
                "email": claims.get("email"), "name": claims.get("name"),
                "groups": claims.get("groups", []),
            }
            return RedirectResponse(url="/", status_code=302)

        @app.get("/auth/logout")
        async def logout(request: Request):
            request.session.pop("user", None)
            return RedirectResponse(url="/", status_code=302)

        @app.get("/auth/me")
        async def me(request: Request):
            user = await self.current_user(request)
            return JSONResponse({
                "user_id": user.user_id, "sub": user.sub, "email": user.email,
                "name": user.name, "groups": user.groups,
            })
