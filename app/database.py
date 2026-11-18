import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).resolve().parent / 'vulnscope.db'

def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    with connect() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                bio TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')
        db.execute('INSERT OR IGNORE INTO users (username, password_hash, bio) VALUES (?, ?, ?)',
                   ('admin', generate_password_hash('admin123'), 'Local security lab administrator'))
        db.execute('INSERT OR IGNORE INTO users (username, password_hash, bio) VALUES (?, ?, ?)',
                   ('analyst', generate_password_hash('analyst123'), 'Local test analyst'))
