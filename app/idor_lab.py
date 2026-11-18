"""VulnScope Phase 2: local-only IDOR training lab.

All records in this file are fictional. The vulnerable endpoint is deliberately
insecure; do not expose this lab to a network or deploy it to production.
"""

from flask import Blueprint, abort, redirect, render_template, request, session, url_for

idor_lab = Blueprint("idor_lab", __name__)

# Synthetic records only: this lab never reads VulnScope's real user database.
DEMO_PROFILES = {
    1: {
        "id": 1,
        "name": "Alice Carter",
        "email": "alice@example.test",
        "role": "Demo Analyst",
        "private_note": "Alice's fictional private project note.",
    },
    2: {
        "id": 2,
        "name": "Bob Rivera",
        "email": "bob@example.test",
        "role": "Demo Reviewer",
        "private_note": "Bob's fictional private review note.",
    },
}


@idor_lab.before_request
def restrict_to_local_lab():
    """Only allow local requests and require the dedicated demo session."""
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403, description="IDOR lab is local-only")

    if request.endpoint != "idor_lab.start" and not session.get("idor_lab_active"):
        return redirect(url_for("idor_lab.start"))


@idor_lab.get("/lab/idor/start")
def start():
    """Create an isolated, fictional session logged in as Alice (user 1)."""
    session["idor_lab_active"] = True
    session["idor_lab_user_id"] = 1
    return redirect(url_for("idor_lab.vulnerable", user_id=1))


def requested_profile_id():
    raw_id = request.args.get("user_id", "1")
    if not raw_id.isdecimal() or len(raw_id) > 5:
        abort(400, description="user_id must be a small positive integer")

    profile_id = int(raw_id)
    if profile_id not in DEMO_PROFILES:
        abort(404, description="Demo profile not found")
    return profile_id


def render_profile(profile_id, mode):
    return render_template(
        "idor_lab.html",
        mode=mode,
        profile=DEMO_PROFILES[profile_id],
        current_user=DEMO_PROFILES[session["idor_lab_user_id"]],
    )


@idor_lab.get("/lab/idor")
def vulnerable():
    """Intentionally flawed: existence check but NO ownership check."""
    profile_id = requested_profile_id()
    return render_profile(profile_id, "vulnerable")


@idor_lab.get("/lab/idor-safe")
def safe():
    """Fix: enforce server-side object authorization before returning data."""
    profile_id = requested_profile_id()
    if profile_id != session.get("idor_lab_user_id"):
        abort(403, description="Access denied: this is not your demo profile")
    return render_profile(profile_id, "safe")
