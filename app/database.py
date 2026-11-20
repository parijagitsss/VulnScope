"""Disposable synthetic data for the local-only VulnScope Portal.
Never import actual account data into this database.
"""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).resolve().parent / 'portal_one_website.db'

@contextmanager
def connect(readonly=False):
    if readonly:
        db = sqlite3.connect(f'file:{DB_PATH.as_posix()}?mode=ro', uri=True)
    else:
        db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA foreign_keys = ON')
        yield db
        if not readonly:
            db.commit()
    finally:
        db.close()


def initialize():
    with connect() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                department TEXT NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                title TEXT NOT NULL,
                department TEXT NOT NULL,
                location TEXT NOT NULL,
                email TEXT NOT NULL,
                directory_visible INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                updated TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            );
            CREATE TABLE IF NOT EXISTS ticket_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ticket_id) REFERENCES tickets (id),
                FOREIGN KEY (author_id) REFERENCES users (id)
            );
        ''')
        if db.execute('SELECT COUNT(*) FROM users').fetchone()[0]:
            return
        accounts = [
            (1,'alice','Alice Carter','alice@example.test','Analyst','Security'),
            (2,'bob','Bob Rivera','bob@example.test','Reviewer','Engineering'),
            (3,'admin','Morgan Lee','morgan@example.test','Administrator','Operations'),
        ]
        for i, username, display_name, email, role, dept in accounts:
            db.execute('INSERT INTO users VALUES (?,?,?,?,?,?,?)',
                       (i,username,display_name,email,role,dept,generate_password_hash('Welcome123!')))
        employees = [
            (1,'alice','Alice Carter','Security Analyst','Security','Mumbai','alice@example.test'),
            (2,'bob','Bob Rivera','Software Engineer','Engineering','Pune','bob@example.test'),
            (3,'morgan','Morgan Lee','Operations Lead','Operations','Bengaluru','morgan@example.test'),
            (4,'priya','Priya Sharma','Product Designer','Design','Mumbai','priya@example.test'),
            (5,'sam','Sam Wilson','IT Support Specialist','IT Support','Hyderabad','sam@example.test'),
            (6,'neha','Neha Kapoor','QA Engineer','Quality','Delhi','neha@example.test'),
            (7,'omar','Omar Khan','Backend Developer','Engineering','Mumbai','omar@example.test'),
            (8,'rhea','Rhea Menon','Customer Success Lead','Support','Chennai','rhea@example.test'),
        ]
        # One private synthetic staff record is deliberately excluded from directory searches.
        # A successful SQL injection incorrectly exposes it alongside ordinary records.
        employees_with_visibility = [(*employee, 1) for employee in employees]
        employees_with_visibility.append((9, 'serviceaudit', 'Internal Audit Service',
            'Restricted Account', 'Internal Audit', 'Private',
            'serviceaudit@example.test', 0))
        db.executemany('INSERT INTO employees VALUES (?,?,?,?,?,?,?,?)',
                       employees_with_visibility)
        tickets = [
            (1041,1,'Unable to access analytics dashboard','The insights dashboard displays a blank chart after login. Please investigate.','Access','High','Open','2026-11-18'),
            (1042,1,'Request access to security metrics','Need read access for the quarterly review meeting.','Permissions','Medium','In progress','2026-11-17'),
            (1043,2,'Internal API documentation unavailable','The API documentation link returns a missing-page error.','Documentation','Medium','Open','2026-11-18'),
            (1044,2,'Production deployment review notes','Confidential fictional deployment notes for Bob’s team.','Engineering','High','In review','2026-11-16'),
            (1045,3,'New employee onboarding checklist','Prepare the onboarding tasks for the next team intake.','Operations','Low','Resolved','2026-11-15'),
        ]
        db.executemany('INSERT INTO tickets VALUES (?,?,?,?,?,?,?,?)',tickets)
        db.executemany('INSERT INTO ticket_comments (ticket_id, author_id, body) VALUES (?,?,?)',[
            (1041,1,'I can reproduce the issue after logging in.'),
            (1041,3,'Thanks — we are reviewing the dashboard service.'),
            (1042,1,'Access request submitted for review.'),
            (1043,2,'The documentation may have moved.'),
            (1044,2,'This is a fictional private ticket for the IDOR exercise.'),
        ])
