"""Educational CSRF lab for VulnScope. Run ONLY on 127.0.0.1.

This blueprint operates on synthetic profile data stored in a session, never
on the real application user database.
"""

import hmac
import secrets

from flask import (
    Blueprint,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

csrf_lab = Blueprint("csrf_lab", __name__)


@csrf_lab.before_request
def restrict_lab_to_localhost():
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)

    if request.endpoint != "csrf_lab.start" and not session.get("csrf_lab_active"):
        if request.method == "GET":
            return redirect(url_for("csrf_lab.start"))
        abort(401)


@csrf_lab.route("/lab/csrf/start", methods=["GET"])
def start():
    # Demo values are independent of real VulnScope user accounts.
    session["csrf_lab_active"] = True
    session.setdefault("csrf_vulnerable_name", "Demo User")
    session.setdefault("csrf_safe_name", "Demo User")
    session.setdefault("csrf_lab_token", secrets.token_urlsafe(32))
    return redirect(url_for("csrf_lab.vulnerable"))


def render_lab(mode):
    is_safe = mode == "safe"
    return render_template(
        "csrf_lab.html",
        mode=mode,
        title="Protected CSRF Lab" if is_safe else "Vulnerable CSRF Lab",
        current_name=session["csrf_safe_name" if is_safe else "csrf_vulnerable_name"],
        csrf_token=session.get("csrf_lab_token") if is_safe else None,
    )


def validate_name():
    name = request.form.get("display_name", "").strip()
    if not 1 <= len(name) <= 60:
        abort(400, "Display name must be 1–60 characters")
    return name


@csrf_lab.route("/lab/csrf", methods=["GET", "POST"])
def vulnerable():
    if request.method == "POST":
        # INTENTIONALLY VULNERABLE: no CSRF token check.
        session["csrf_vulnerable_name"] = validate_name()
        return redirect(url_for("csrf_lab.vulnerable"))
    return render_lab("vulnerable")


@csrf_lab.route("/lab/csrf-safe", methods=["GET", "POST"])
def safe():
    if request.method == "POST":
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_lab_token", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(403, "Invalid CSRF token")

        session["csrf_safe_name"] = validate_name()
        session["csrf_lab_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("csrf_lab.safe"))
    return render_lab("safe")
