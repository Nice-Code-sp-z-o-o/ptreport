"""Flask application factory."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from ptreport import __version__, db, rendering, security

MAX_UPLOAD_BYTES = 256 * 1024 * 1024  # JSON imports carry screenshots and files; the app only listens locally


def default_data_dir() -> Path:
    env = os.environ.get("PTREPORT_DATA_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(Path.home(), ".local", "share")
    return Path(base) / "ptreport" / "data"


def create_app(config: dict | None = None) -> Flask:
    config = dict(config or {})
    data_dir = Path(config.pop("DATA_DIR", None) or default_data_dir()).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(data_dir, 0o700)
    except OSError:
        pass

    app = Flask(__name__)
    app.config.update(
        DATA_DIR=str(data_dir),
        DATABASE=str(data_dir / "ptreport.db"),
        API_TOKEN_FILE=str(data_dir / "api_token"),
        ALLOWED_HOSTS=set(security.LOOPBACK_HOSTS),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
        MAX_FORM_MEMORY_SIZE=32 * 1024 * 1024,
        SESSION_COOKIE_NAME="ptreport_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        JSON_SORT_KEYS=False,
        VERSION=__version__,
    )
    app.config.update(config)
    app.config["ALLOWED_HOSTS"] = {h.lower() for h in app.config["ALLOWED_HOSTS"]}
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = security.read_or_create_secret(data_dir / "secret_key", 48)
    if not app.config.get("API_TOKEN"):
        app.config["API_TOKEN"] = security.read_or_create_secret(Path(app.config["API_TOKEN_FILE"]))

    app.logger.setLevel(logging.INFO)
    db.init_app(app)
    if app.config.get("SEED_TEMPLATES", True):
        from ptreport import repo

        conn = db.connect(app.config["DATABASE"])
        try:
            repo.seed_templates(conn)
        finally:
            conn.close()
    security.init_app(app)
    rendering.init_app(app)

    from ptreport.api import bp as api_bp
    from ptreport.views import bp as web_bp

    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def _inject():
        return {"app_version": __version__}

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        if request.blueprint == "api" or request.path.startswith("/api/"):
            return jsonify(error=exc.name.lower().replace(" ", "_"), message=exc.description), exc.code
        return render_template("error.html", error=exc), exc.code

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception):
        app.logger.exception("Unhandled error")
        if request.path.startswith("/api/"):
            return jsonify(error="internal_error", message="Internal error."), 500
        return render_template("error.html", error=None), 500

    return app
