"""Security controls for a local web app.

* Host header allow-list - blocks DNS-rebinding attacks from malicious websites
  open in the pentester's browser.
* CSRF tokens on every state-changing browser request (SameSite=Strict cookie
  as defence in depth).
* Bearer token for the JSON API (used by the Burp extension).
* Strict security headers / CSP (no inline scripts at all).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

from flask import Flask, abort, current_app, g, jsonify, request, session

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; frame-src blob:; "
    "base-uri 'none'"
)


def read_or_create_secret(path: Path, nbytes: int = 32) -> str:
    """Read a secret from ``path`` or create it with 0600 permissions."""
    try:
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    return write_secret(path, secrets.token_urlsafe(nbytes))


def write_secret(path: Path, value: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value)
    os.replace(tmp, path)
    return value


def regenerate_api_token(app: Flask) -> str:
    token = write_secret(Path(app.config["API_TOKEN_FILE"]), secrets.token_urlsafe(32))
    app.config["API_TOKEN"] = token
    return token


def hostname_of(host_header: str) -> str:
    host = host_header.strip().lower()
    if host.startswith("["):  # [::1]:5055
        end = host.find("]")
        return host[1:end] if end != -1 else host
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


def _is_api_request() -> bool:
    return request.blueprint == "api"


def init_app(app: Flask) -> None:
    @app.before_request
    def _check_host():
        allowed = app.config["ALLOWED_HOSTS"]
        if hostname_of(request.headers.get("Host", "")) not in allowed:
            current_app.logger.warning("Rejected request with untrusted Host header")
            abort(400)

    @app.before_request
    def _check_csrf():
        if request.method in SAFE_METHODS or _is_api_request():
            return None
        sent = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
            current_app.logger.warning("Rejected request with missing/invalid CSRF token")
            abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")
        return None

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.path != "/static" and not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.jinja_env.globals["csrf_token"] = csrf_token


FULL_ACCESS = frozenset({"*"})
INTEGRATION_TOKEN_PREFIX = "ptr_"  # noqa: S105 - marks integration tokens, not a secret


def new_integration_token() -> tuple[str, str]:
    """A fresh integration token and its SHA-256 (only the hash is stored; the token is shown once)."""
    token = INTEGRATION_TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, token_sha256(token)


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _unauthorized():
    current_app.logger.warning("Rejected API request with missing/invalid token")
    response = jsonify(error="unauthorized", message="Missing or invalid API token.")
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="ptreport"'
    return response


def require_api_token():
    """before_request hook for the API blueprint.

    The main API token has full access. Integration tokens (Settings -> Integrations) are looked up by their
    SHA-256 and carry scopes (``read``, ``propose``); ``g.api_scopes`` / ``g.api_token_id`` tell the endpoints
    which one was used."""
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token or len(token) > 200:
        return _unauthorized()
    expected = current_app.config["API_TOKEN"]
    if hmac.compare_digest(token.encode(), expected.encode()):
        g.api_scopes, g.api_token_id = FULL_ACCESS, None
        return None
    if token.startswith(INTEGRATION_TOKEN_PREFIX):
        from ptreport import repo
        from ptreport.db import get_db

        digest = token_sha256(token)
        row = repo.find_integration_token(get_db(), digest)
        if row is not None and hmac.compare_digest(row["token_sha256"].encode(), digest.encode()):
            g.api_scopes = frozenset(s for s in row["scopes"].split(",") if s)
            g.api_token_id = row["id"]
            repo.mark_integration_token_used(get_db(), row["id"])
            return None
    return _unauthorized()
