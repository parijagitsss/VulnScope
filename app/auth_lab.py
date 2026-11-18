"""VulnScope VS-005: localhost training lab for login rate limiting.

Only synthetic test-account data is used. Do not deploy this Blueprint.
"""

from __future__ import annotations

import threading
import time
from flask import Blueprint, abort, jsonify, redirect, render_template, request, session, url_for

auth_lab = Blueprint("auth_lab", __name__)
MAX_FAILURES = 3
LOCK_SECONDS = 120
# Ephemeral classroom-only tracking. Production needs a shared persistent store.
_failures: dict[tuple[str, str], tuple[int, float]] = {}
_guard = threading.Lock()


def _identity() -> tuple[str, str]:
    # Fixed demo account; no real user profiles or passwords are read.
    return (request.remote_addr or "unknown", "labuser")


@auth_lab.before_request
def local_lab_only():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)
    if request.endpoint != "auth_lab.start" and not session.get("auth_lab_active"):
        if request.method == "GET":
            return redirect(url_for("auth_lab.start"))
        abort(401, "Open /lab/auth/start first")


@auth_lab.get("/lab/auth/start")
def start():
    session["auth_lab_active"] = True
    session.setdefault("auth_lab_weak_attempts", 0)
    return redirect(url_for("auth_lab.home"))


@auth_lab.get("/lab/auth")
def home():
    return render_template("auth_lab.html", max_failures=MAX_FAILURES)


def _dummy_reject():
    # All sample passwords are intentionally rejected; never authenticates anyone.
    supplied = request.form.get("password", "")
    if not supplied or len(supplied) > 100:
        return jsonify(error="Provide a nonempty demo password (max 100 characters)"), 400
    return None


@auth_lab.post("/lab/auth/vulnerable/attempt")
def vulnerable_attempt():
    invalid = _dummy_reject()
    if invalid:
        return invalid
    count = session.get("auth_lab_weak_attempts", 0) + 1
    session["auth_lab_weak_attempts"] = count
    # INSECURE BY DESIGN: no rate limit, cooldown, or lockout.
    return jsonify(status="rejected", message="Incorrect demo password", attempts=count), 401


@auth_lab.post("/lab/auth/safe/attempt")
def safe_attempt():
    invalid = _dummy_reject()
    if invalid:
        return invalid
    key = _identity()
    now = time.monotonic()
    with _guard:
        count, until = _failures.get(key, (0, 0.0))
        if until and now >= until:
            count, until = 0, 0.0
        if count >= MAX_FAILURES and now < until:
            return jsonify(status="limited", message="Too many attempts; retry later", attempts=count), 429
        count += 1
        if count >= MAX_FAILURES:
            until = now + LOCK_SECONDS
        _failures[key] = (count, until)
    return jsonify(status="rejected", message="Invalid credentials", attempts=count), 401


@auth_lab.post("/lab/auth/reset")
def reset():
    # Explicit, local-only lab reset for repeatable demonstrations.
    with _guard:
        _failures.pop(_identity(), None)
    session["auth_lab_weak_attempts"] = 0
    return jsonify(status="reset", message="Demo counters reset")
