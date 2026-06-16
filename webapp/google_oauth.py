"""Optional 'Sign in with Google' (OAuth 2.0 / OpenID Connect).

Enabled only when credentials are present — either ~/.bk_google_oauth.json
({"client_id": "...", "client_secret": "..."}) or the GOOGLE_CLIENT_ID /
GOOGLE_CLIENT_SECRET env vars. Until then enabled() is False and the UI hides the
button, so this is completely inert.
"""
import json
import os
from urllib.parse import urlencode

import httpx

from bk_common import config

PUBLIC_ORIGIN = os.environ.get("BK_PUBLIC_ORIGIN", "https://berkkarabacak.com").rstrip("/")
REDIRECT_URI = PUBLIC_ORIGIN + "/account/api/auth/google/callback"

_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN = "https://oauth2.googleapis.com/token"
_USERINFO = "https://www.googleapis.com/oauth2/v3/userinfo"
_CONF_FILE = config.HOME / ".bk_google_oauth.json"


def _creds():
    # 1) explicit env vars win.
    cid = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    csec = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    if cid and csec:
        return cid, csec
    # 2) ~/.bk_google_oauth.json — accepts a flat {client_id, client_secret} OR
    #    Google's downloaded *Web* client file {"web": {...}}. A Desktop/"installed"
    #    client is intentionally ignored (its localhost-only redirect can't serve a
    #    hosted web callback), so a wrong-type file leaves SSO off rather than broken.
    try:
        d = json.loads(_CONF_FILE.read_text(encoding="utf-8"))
        node = d.get("web") or d
        return (node.get("client_id") or "").strip(), (node.get("client_secret") or "").strip()
    except Exception:
        return "", ""


def enabled() -> bool:
    cid, csec = _creds()
    return bool(cid and csec)


def auth_url(state: str) -> str:
    cid, _ = _creds()
    return _AUTH + "?" + urlencode({
        "response_type": "code", "client_id": cid, "redirect_uri": REDIRECT_URI,
        "scope": "openid email profile", "state": state,
        "access_type": "online", "prompt": "select_account",
    })


def fetch_user(code: str) -> dict:
    """Exchange the auth code for the user's verified email + name, or raise."""
    cid, csec = _creds()
    with httpx.Client(timeout=20.0) as c:
        tok = c.post(_TOKEN, data={
            "code": code, "client_id": cid, "client_secret": csec,
            "redirect_uri": REDIRECT_URI, "grant_type": "authorization_code"})
        if tok.status_code >= 400:
            raise ValueError("token exchange failed")
        access = tok.json().get("access_token")
        if not access:
            raise ValueError("no access token")
        ui = c.get(_USERINFO, headers={"Authorization": "Bearer %s" % access})
        if ui.status_code >= 400:
            raise ValueError("userinfo failed")
    info = ui.json()
    email = (info.get("email") or "").strip().lower()
    if not email or info.get("email_verified") not in (True, "true"):
        raise ValueError("email not verified")   # reject if missing or false
    sub = (info.get("sub") or "").strip()
    if not sub:
        raise ValueError("no subject")
    return {"sub": sub, "email": email, "name": info.get("name") or email.split("@")[0]}
