import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request

from oidc_auth import OIDCAuth, OidcConfig, SessionUser, DEV_OWNER


def _app(config, cb=lambda claims: 1):
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key="test-secret")
    oidc = OIDCAuth(app, find_or_create_user=cb, config=config)

    @app.get("/whoami")
    def whoami(user: SessionUser = Depends(oidc.current_user)):
        return {"user_id": user.user_id, "groups": user.groups}

    @app.get("/admin-only")
    def admin_only(user: SessionUser = Depends(oidc.require_group("admins"))):
        return {"ok": True}

    return app, oidc


DISABLED = OidcConfig(issuer="", client_id="", client_secret="")
ENABLED = OidcConfig(issuer="https://idp.test", client_id="cid", client_secret="sec",
                     redirect_uri="https://app.test/auth/callback")


def test_config_enabled_flag():
    assert DISABLED.enabled is False
    assert ENABLED.enabled is True


def test_disabled_mode_returns_dev_owner():
    app, _ = _app(DISABLED)
    r = TestClient(app).get("/whoami")
    assert r.status_code == 200
    assert r.json() == {"user_id": DEV_OWNER.user_id, "groups": DEV_OWNER.groups}


def test_enabled_without_session_is_401():
    app, _ = _app(ENABLED)
    r = TestClient(app).get("/whoami")
    assert r.status_code == 401


def test_require_group_allows_dev_owner_admin():
    app, _ = _app(DISABLED)
    assert TestClient(app).get("/admin-only").status_code == 200


def test_require_group_forbids_non_member():
    app, oidc = _app(ENABLED, lambda c: 9)

    @app.get("/seed-session")
    async def seed(request: Request):
        request.session["user"] = {"user_id": 9, "sub": "s", "email": None,
                                   "name": None, "groups": ["family"]}
        return {"ok": True}

    client = TestClient(app)
    client.get("/seed-session")            # now authenticated, but not in "admins"
    assert client.get("/admin-only").status_code == 403


from unittest.mock import AsyncMock
from starlette.responses import RedirectResponse


def test_login_disabled_is_404():
    app, _ = _app(DISABLED)
    assert TestClient(app).get("/auth/login").status_code == 404


def test_me_disabled_returns_dev_owner():
    app, _ = _app(DISABLED)
    r = TestClient(app).get("/auth/me")
    assert r.status_code == 200 and r.json()["user_id"] == DEV_OWNER.user_id


def test_me_enabled_without_session_is_401():
    app, _ = _app(ENABLED)
    assert TestClient(app).get("/auth/me").status_code == 401


def test_callback_creates_session_via_find_or_create():
    seen = {}
    def cb(claims):
        seen["claims"] = claims
        return 42
    app, oidc = _app(ENABLED, cb)
    oidc._oauth.idp.authorize_access_token = AsyncMock(return_value={
        "userinfo": {"sub": "abc-123", "email": "fern@x.com", "name": "Fern", "groups": ["family"]}})
    client = TestClient(app)
    r = client.get("/auth/callback", follow_redirects=False)
    assert r.status_code in (302, 307)
    assert seen["claims"]["sub"] == "abc-123"
    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json() == {"user_id": 42, "sub": "abc-123", "email": "fern@x.com",
                         "name": "Fern", "groups": ["family"]}


def test_logout_clears_session():
    app, oidc = _app(ENABLED, lambda c: 7)
    oidc._oauth.idp.authorize_access_token = AsyncMock(return_value={
        "userinfo": {"sub": "s", "email": None, "name": None, "groups": []}})
    client = TestClient(app)
    client.get("/auth/callback", follow_redirects=False)
    assert client.get("/auth/me").status_code == 200
    client.get("/auth/logout", follow_redirects=False)
    assert client.get("/auth/me").status_code == 401


def test_login_enabled_redirects():
    app, oidc = _app(ENABLED)
    oidc._oauth.idp.authorize_redirect = AsyncMock(
        return_value=RedirectResponse("https://idp.test/authorize?x=1"))
    r = TestClient(app).get("/auth/login", follow_redirects=False)
    assert r.status_code in (302, 307)
    oidc._oauth.idp.authorize_redirect.assert_awaited()


def test_callback_without_sub_is_401():
    app, oidc = _app(ENABLED, lambda c: 1)
    oidc._oauth.idp.authorize_access_token = AsyncMock(return_value={"userinfo": {"email": "x@y.com"}})
    r = TestClient(app).get("/auth/callback", follow_redirects=False)
    assert r.status_code == 401


def test_callback_validation_failure_redirects_to_login():
    app, oidc = _app(ENABLED, lambda c: 1)
    oidc._oauth.idp.authorize_access_token = AsyncMock(side_effect=Exception("bad token"))
    r = TestClient(app).get("/auth/callback", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/auth/login"


def test_callback_validation_failure_clears_session():
    app, oidc = _app(ENABLED, lambda c: 1)
    # first, a good login establishes a session
    oidc._oauth.idp.authorize_access_token = AsyncMock(return_value={
        "userinfo": {"sub": "s", "email": None, "name": None, "groups": []}})
    client = TestClient(app)
    client.get("/auth/callback", follow_redirects=False)
    assert client.get("/auth/me").status_code == 200
    # now a failing callback must clear the session
    oidc._oauth.idp.authorize_access_token = AsyncMock(side_effect=Exception("bad"))
    client.get("/auth/callback", follow_redirects=False)
    assert client.get("/auth/me").status_code == 401


def test_login_503_when_idp_unreachable():
    app, oidc = _app(ENABLED)
    oidc._oauth.idp.authorize_redirect = AsyncMock(side_effect=Exception("idp down"))
    r = TestClient(app).get("/auth/login", follow_redirects=False)
    assert r.status_code == 503
