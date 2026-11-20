"""VulnScope: one fictional employee portal used for a LOCAL penetration-testing exercise.

This file intentionally contains security mistakes. Never deploy this application or
bind it to a public/network interface. Use synthetic data only, on 127.0.0.1.
Remediate the SAME application after testing it; no parallel 'secure' pages exist.
"""
from __future__ import annotations
import hmac
import os
import secrets
import sqlite3
import threading
import time
from threading import Lock
from functools import wraps
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from database import connect, initialize

app = Flask(__name__)
app.secret_key = os.environ.get('VULNSCOPE_SECRET_KEY') or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
initialize()

# Track repeated failed login attempts.
_login_lock = Lock()
_login_failures = {}



@app.before_request
def local_only_and_user():
    # Allow access only from the local computer.
    if request.remote_addr not in {'127.0.0.1', '::1'}:
        abort(403)

    g.user = None

    if 'portal_user_id' in session:
        with connect(readonly=True) as db:
            g.user = db.execute(
                'SELECT * FROM users WHERE id = ?',
                (session['portal_user_id'],)
            ).fetchone()



def login_required(view):
    @wraps(view)
    def inner(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return inner


def csrf_token():
    if '_portal_csrf' not in session:
        session['_portal_csrf'] = secrets.token_urlsafe(32)
    return session['_portal_csrf']


def verify_csrf():
    given = request.form.get('_csrf_token', '')
    expected = session.get('_portal_csrf', '')
    if not given or not expected or not hmac.compare_digest(given, expected):
        abort(403, description='Missing or invalid CSRF token')


@app.context_processor
def template_globals():
    return {'current_user': g.get('user'), 'csrf_token': csrf_token}


@app.get('/')
def home():
    return redirect(url_for('dashboard') if g.user else url_for('login'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        verify_csrf()

        username = request.form.get(
            'username', ''
        ).strip().lower()[:40]

        password = request.form.get(
            'password', ''
        )[:150]

        # Rate limiting: track failures by IP and username.
        key = (request.remote_addr, username)
        now = time.monotonic()

        with _login_lock:
            count, locked_until = _login_failures.get(
                key, (0, 0.0)
            )

            # Reset attempts after the lockout expires.
            if locked_until and now >= locked_until:
                _login_failures.pop(key, None)
                count = 0
                locked_until = 0.0

            # Block further attempts temporarily.
            if count >= 3 and now < locked_until:
                flash(
                    'Too many login attempts. '
                    'Please try again later.',
                    'error'
                )
                return render_template('login.html'), 429

        # Check credentials as before.
        with connect(readonly=True) as db:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()

        if user and check_password_hash(
            user['password_hash'], password
        ):
            # Clear failed attempts after successful login.
            with _login_lock:
                _login_failures.pop(key, None)

            session.clear()
            session['portal_user_id'] = user['id']
            session['_portal_csrf'] = secrets.token_urlsafe(32)

            return redirect(url_for('dashboard'))

        # Incorrect password: increase failure counter.
        with _login_lock:
            count, locked_until = _login_failures.get(
                key, (0, 0.0)
            )
            count += 1

            if count >= 3:
                locked_until = time.monotonic() + 120

            _login_failures[key] = (count, locked_until)

        flash('Invalid username or password.', 'error')
        return render_template('login.html'), 401

    return render_template('login.html')


@app.post('/logout')
def logout():
    verify_csrf()
    session.clear()
    return redirect(url_for('login'))


@app.get('/dashboard')
@login_required
def dashboard():
    with connect(readonly=True) as db:
        my_tickets = db.execute('SELECT * FROM tickets WHERE owner_id = ? ORDER BY id DESC',
                                (g.user['id'],)).fetchall()
        team_count = db.execute('SELECT COUNT(*) FROM employees WHERE directory_visible = 1').fetchone()[0]
        open_count = db.execute("SELECT COUNT(*) FROM tickets WHERE status != 'Resolved'").fetchone()[0]
    return render_template('dashboard.html', tickets=my_tickets, team_count=team_count,
                           open_count=open_count)


@app.get('/employees')
@login_required
def employees():
    username = request.args.get('username', '').strip()[:80]
    rows = []
    if username:
        with connect(readonly=True) as db:
            
# FIXED: Use a parameterized query to prevent SQL injection.
            sql = ("SELECT id, username, name, title, department, location, email "
                "FROM employees WHERE directory_visible = 1 AND username = ?")
            try:
                rows = db.execute(sql, (username,)).fetchall()

            except sqlite3.Error:
                flash('The directory lookup could not be completed.', 'error')
    return render_template('employees.html', people=rows, username=username)


@app.get('/tickets')
@login_required
def tickets():
    with connect(readonly=True) as db:
        rows = db.execute('SELECT * FROM tickets WHERE owner_id = ? ORDER BY id DESC',
                          (g.user['id'],)).fetchall()
    return render_template('tickets.html', tickets=rows)


@app.get('/tickets/<int:ticket_id>')
@login_required
def ticket_detail(ticket_id):
    with connect(readonly=True) as db:
        ticket = db.execute("""SELECT tickets.*, users.display_name AS owner_name
                               FROM tickets JOIN users ON tickets.owner_id=users.id
                               WHERE tickets.id = ?""", (ticket_id,)).fetchone()
        if not ticket:
            abort(404)
        

        # FIXED: Only the ticket owner can view this ticket.
        if ticket['owner_id'] != g.user['id']:
            abort(403, description='You cannot view this ticket')

        comments = db.execute("""SELECT ticket_comments.body, ticket_comments.created,
                                users.display_name AS author_name
                                FROM ticket_comments JOIN users ON users.id=ticket_comments.author_id
                                WHERE ticket_comments.ticket_id=? ORDER BY ticket_comments.id""",
                              (ticket_id,)).fetchall()

    return render_template('ticket_detail.html', ticket=ticket, comments=comments)



@app.post('/tickets/<int:ticket_id>/comments')
@login_required
def add_ticket_comment(ticket_id):
    verify_csrf()
    text = request.form.get('body', '').strip()[:500]
    with connect() as db:
        ticket = db.execute('SELECT * FROM tickets WHERE id=?', (ticket_id,)).fetchone()
        if not ticket:
            abort(404)
        if ticket['owner_id'] != g.user['id']:
            abort(403)
        if text:
            db.execute('INSERT INTO ticket_comments (ticket_id, author_id, body) VALUES (?,?,?)',
                       (ticket_id, g.user['id'], text))
    flash('Comment posted.', 'success')
    return redirect(url_for('ticket_detail', ticket_id=ticket_id))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        
        # FIXED: Reject profile updates without a valid CSRF token.
        verify_csrf()

        new_name = request.form.get('display_name', '').strip()[:60]
        if not new_name:
            flash('Please enter a display name.', 'error')
        else:
            with connect() as db:
                db.execute('UPDATE users SET display_name=? WHERE id=?',
                           (new_name, g.user['id']))
            flash('Profile updated.', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html')


@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', code=403, message='Access denied',
                           detail='You do not have permission to view this resource.'), 403


@app.errorhandler(404)
def missing(error):
    return render_template('error.html', code=404, message='Page not found',
                           detail='That page or ticket does not exist in this demo.'), 404


if __name__ == '__main__':    
    app.run(host='127.0.0.1', port=int(os.environ.get('PORT', '5000')), debug=False)
