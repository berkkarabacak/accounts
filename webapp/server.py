"""berkkarabacak.com central Accounts service — HTTP layer.

Owns identity (email + password) and the shared Jira credential vault. Every app
on the domain shares the bk_session cookie, so signing in here signs you in
everywhere. Data access lives in store.py; this file is just routes.

  /api/*       public, session-authenticated (proxied at /account/api/*)
  /internal/*  localhost only (nginx blocks /account/internal); shared-key guarded
"""
import os
import secrets
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from bk_common import config, jira, session

from . import google_oauth, store

STATIC_DIR = Path(__file__).resolve().parent / "static"

store.init_db()
app = FastAPI(title="berkkarabacak.com Accounts")
session.add_session(app)


def require_user(request: Request) -> dict:
    uid = request.session.get("uid")
    row = store.get_user_by_id(uid) if uid else None
    if not row:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Not signed in")
    return store.user_public(row)


def _sign_in(request: Request, user: dict):
    request.session.clear()          # rotate: drop any pre-auth / fixated contents
    request.session["uid"] = user["id"]
    request.session["email"] = user["email"]


def _validate_jira(base_url, email, token) -> dict:
    try:
        return jira.validate(base_url, email, token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class RegisterBody(BaseModel):
    email: str
    password: str
    display_name: Optional[str] = ""


class LoginBody(BaseModel):
    email: str
    password: str


@app.post("/api/register")
def register(body: RegisterBody, request: Request):
    if "@" not in (body.email or "") or len(body.email) < 4:
        raise HTTPException(status_code=400, detail="Enter a valid email.")
    if len(body.password or "") < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    try:
        user = store.create_user(body.email, body.password, body.display_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _sign_in(request, user)
    return {"ok": True, "user": user}


@app.post("/api/login")
def login(body: LoginBody, request: Request):
    row = store.get_user(body.email)
    if not store.check_password(row, body.password):
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    user = store.user_public(row)
    _sign_in(request, user)
    return {"ok": True, "user": user}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(require_user)):
    return {"user": user}


# -- optional Google sign-in (inert until credentials are configured) --
@app.get("/api/auth/config")
def auth_config():
    return {"google": google_oauth.enabled()}


@app.get("/api/auth/google/login")
def google_login(request: Request):
    if not google_oauth.enabled():
        raise HTTPException(status_code=404, detail="Google sign-in is not configured.")
    state = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state
    return RedirectResponse(google_oauth.auth_url(state), status_code=302)


@app.get("/api/auth/google/callback")
def google_callback(request: Request, code: str = "", state: str = ""):
    if not google_oauth.enabled():
        raise HTTPException(status_code=404)
    if not code or not state or state != request.session.get("oauth_state"):
        return RedirectResponse("/account/?auth_error=google", status_code=302)
    request.session.pop("oauth_state", None)
    try:
        g = google_oauth.fetch_user(code)
        user = store.find_or_create_google_user(g["sub"], g["email"], g["name"])
    except ValueError:
        # e.g. that email already belongs to a password account — don't auto-link.
        return RedirectResponse("/account/?auth_error=exists", status_code=302)
    except Exception:
        return RedirectResponse("/account/?auth_error=google", status_code=302)
    _sign_in(request, user)
    return RedirectResponse("/account/", status_code=302)


# --------------------------------------------------------------------------- #
# Connections (vault)
# --------------------------------------------------------------------------- #
class ConnBody(BaseModel):
    name: str
    sites: List[str]            # one credential can serve several sites
    email: str
    token: str
    ctype: Optional[str] = "jira-cloud"
    verify: Optional[bool] = True


class ConnPatch(BaseModel):
    name: Optional[str] = None
    sites: Optional[List[str]] = None
    email: Optional[str] = None
    token: Optional[str] = None
    verify: Optional[bool] = False


@app.get("/api/connections")
def list_connections(user=Depends(require_user)):
    return {"connections": store.list_connections(user["id"])}


@app.post("/api/connections")
def add_connection(body: ConnBody, user=Depends(require_user)):
    sites = [s for s in (body.sites or []) if s and s.strip()]
    if not sites:
        raise HTTPException(status_code=400, detail="Enter at least one site URL.")
    if body.verify:
        _validate_jira(sites[0], body.email, body.token)   # token is account-scoped; first site proves it
    try:
        conn = store.add_connection(user["id"], body.name, sites, body.email, body.token, body.ctype)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "connection": conn}


@app.put("/api/connections/{cid}")
def update_connection(cid: int, body: ConnPatch, user=Depends(require_user)):
    row = store.get_connection(user["id"], cid)
    if not row:
        raise HTTPException(status_code=404, detail="No such connection")
    if body.verify and body.sites:
        _validate_jira(body.sites[0], body.email or row["email"],
                       body.token or store.dec(row["token_enc"]))
    try:
        conn = store.update_connection(user["id"], cid, body.name, body.sites, body.email, body.token)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "connection": conn}


@app.delete("/api/connections/{cid}")
def remove_connection(cid: int, user=Depends(require_user)):
    if not store.delete_connection(user["id"], cid):
        raise HTTPException(status_code=404, detail="No such connection")
    return {"ok": True}


@app.post("/api/connections/{cid}/test")
def test_connection(cid: int, user=Depends(require_user)):
    full = store.resolve(user["id"], cid)
    if not full:
        raise HTTPException(status_code=404, detail="No such connection")
    # Check the token against EVERY site so the user sees where they actually have access.
    results = []
    for site in full.get("sites", []):
        try:
            info = _validate_jira(site, full["email"], full["token"])
            results.append({"host": store.host(site), "ok": True, "displayName": info.get("displayName")})
        except HTTPException as e:
            results.append({"host": store.host(site), "ok": False, "detail": e.detail})
    ok_count = sum(1 for r in results if r["ok"])
    return {"ok": ok_count > 0, "results": results, "ok_count": ok_count, "total": len(results)}


# --------------------------------------------------------------------------- #
# Internal API — localhost only, shared-key guarded. Used by the other apps.
# --------------------------------------------------------------------------- #
def _require_internal(request: Request):
    provided = request.headers.get("X-Internal-Key") or ""
    # Fail closed: an empty configured key is never valid; constant-time compare.
    if not config.INTERNAL_KEY or not secrets.compare_digest(provided, config.INTERNAL_KEY):
        raise HTTPException(status_code=403, detail="forbidden")


@app.get("/internal/connections")
def internal_connections(uid: int, request: Request):
    _require_internal(request)
    return {"connections": store.list_connections(uid)}


class ResolveBody(BaseModel):
    uid: int
    id: int


@app.post("/internal/resolve")
def internal_resolve(body: ResolveBody, request: Request):
    _require_internal(request)
    full = store.resolve(body.uid, body.id)
    if not full:
        raise HTTPException(status_code=404, detail="No such connection")
    return full


class UpsertBody(BaseModel):
    uid: int
    ctype: Optional[str] = "jira-cloud"
    name: str
    base_url: str
    email: str
    token: str


@app.post("/internal/upsert_connection")
def internal_upsert(body: UpsertBody, request: Request):
    _require_internal(request)
    rid = store.upsert_connection(body.uid, body.base_url, body.email, body.token, body.ctype, body.name)
    return {"ok": True, "id": rid}


class DeleteConnsBody(BaseModel):
    uid: int
    ctype: Optional[str] = "jira-cloud"


@app.post("/internal/delete_connections")
def internal_delete_conns(body: DeleteConnsBody, request: Request):
    _require_internal(request)
    store.delete_connections(body.uid, body.ctype)
    return {"ok": True}


class VerifyBody(BaseModel):
    email: str
    password: str


@app.post("/internal/verify")
def internal_verify(body: VerifyBody, request: Request):
    _require_internal(request)
    row = store.get_user(body.email)
    if not store.check_password(row, body.password):
        raise HTTPException(status_code=401, detail="Wrong email or password.")
    return {"user": store.user_public(row)}


class RegBody(VerifyBody):
    display_name: Optional[str] = ""


@app.post("/internal/register")
def internal_register(body: RegBody, request: Request):
    _require_internal(request)
    if "@" not in (body.email or ""):
        raise HTTPException(status_code=400, detail="Enter a valid email.")
    if len(body.password or "") < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    try:
        user = store.create_user(body.email, body.password, body.display_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"user": user}


# Static account UI mounted last so /api and /internal win.
app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webapp.server:app", host="127.0.0.1",
                port=int(os.environ.get("PORT", "8820")), reload=False)
