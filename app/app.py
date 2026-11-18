import os
import sqlite3
import secrets
from functools import wraps
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash
from database import connect, init_db

app = Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('VULNSCOPE_SECRET_KEY', secrets.token_hex(32)),
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax')
init_db()

@app.before_request
def load_user():
    g.user = None
    if 'user_id' in session:
        with connect() as db:
            g.user = db.execute('SELECT id, username, bio FROM users WHERE id = ?',
                                (session['user_id'],)).fetchone()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

def csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = csrf_token

@app.before_request
def verify_csrf():
    if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        token = request.form.get('_csrf_token', '')
        if not secrets.compare_digest(token, session.get('_csrf_token', '')) or not token:
            abort(400, 'Invalid CSRF token')

@app.route('/')
def index():
    return redirect(url_for('dashboard' if g.user else 'login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        with connect() as db:
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    with connect() as db:
        comments = db.execute('''SELECT comments.id, comments.body, comments.created_at,
                                 users.username FROM comments JOIN users ON users.id=comments.user_id
                                 ORDER BY comments.id DESC LIMIT 30''').fetchall()
    return render_template('dashboard.html', comments=comments)

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    if user_id != g.user['id']:
        abort(403)
    return render_template('profile.html')

@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    bio = request.form.get('bio', '').strip()[:300]
    with connect() as db:
        db.execute('UPDATE users SET bio=? WHERE id=?', (bio, g.user['id']))
    flash('Profile updated', 'success')
    return redirect(url_for('profile', user_id=g.user['id']))

@app.route('/comments', methods=['POST'])
@login_required
def add_comment():
    body = request.form.get('body', '').strip()[:1000]
    if body:
        with connect() as db:
            db.execute('INSERT INTO comments(user_id,body) VALUES (?,?)', (g.user['id'], body))
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


# Phase 2: SQL Injection Lab
# Deliberately vulnerable — localhost testing only.

@app.route("/lab/sqli")
def sqli_lab():
    username = request.args.get("username", "")

    # Separate in-memory database with dummy data
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE lab_users (id INTEGER, username TEXT)"
    )
    conn.executemany(
        "INSERT INTO lab_users VALUES (?, ?)",
        [
            (1, "admin"),
            (2, "analyst"),
            (3, "tester")
        ]
    )

    # INTENTIONALLY UNSAFE:
    # User input is concatenated into the SQL query.
    query = (
        "SELECT id, username FROM lab_users "
        f"WHERE username = '{username}'"
    )

    try:
        rows = conn.execute(query).fetchall()
        return {
            "lab": "SQL Injection",
            "query": query,
            "results": [
                {"id": row[0], "username": row[1]}
                for row in rows
            ]
        }
    except sqlite3.Error:
        return {"error": "Invalid SQL query"}, 400
    finally:
        conn.close()


@app.route("/lab/sqli-safe")
def sqli_safe():
    username = request.args.get("username", "")

    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE lab_users (id INTEGER, username TEXT)"
    )
    conn.executemany(
        "INSERT INTO lab_users VALUES (?, ?)",
        [
            (1, "admin"),
            (2, "analyst"),
            (3, "tester")
        ]
    )

    # SECURE: Parameterized query
    query = (
        "SELECT id, username FROM lab_users "
        "WHERE username = ?"
    )

    try:
        rows = conn.execute(query, (username,)).fetchall()
        return {
            "lab": "SQL Injection Remediation",
            "results": [
                {"id": row[0], "username": row[1]}
                for row in rows
            ]
        }
    finally:
        conn.close()


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
