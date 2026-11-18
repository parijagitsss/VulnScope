"""VulnScope reflected XSS demo. Intentionally vulnerable: localhost lab ONLY."""

from flask import Blueprint, abort, render_template, request

xss_lab = Blueprint("xss_lab", __name__)


@xss_lab.before_request
def block_nonlocal_requests():
    # Defense in depth; also run Flask with host="127.0.0.1".
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        abort(403)


def show_xss_page(mode):
    comment = request.args.get("comment", "")
    if len(comment) > 300:
        abort(400, "Lab input must be 300 characters or fewer")
    return render_template("xss_lab.html", comment=comment, mode=mode)


@xss_lab.route("/lab/xss", methods=["GET"])
def vulnerable():
    return show_xss_page("vulnerable")


@xss_lab.route("/lab/xss-safe", methods=["GET"])
def safe():
    return show_xss_page("safe")
