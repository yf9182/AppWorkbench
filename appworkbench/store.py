"""SQLite state, append-only audit and machine-wide publisher locks."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import uuid

from .errors import WorkbenchError
from .security import confined, digest, now, private_dir, scan_sensitive

class Store:
    def __init__(self, root):
        self.root = Path(root).resolve()
        private_dir(self.root)
        directory = private_dir(confined(self.root, 'state'))
        self.path = confined(self.root, 'state/workbench.sqlite')
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.row_factory = sqlite3.Row
        os.chmod(self.path, 0o600)
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA busy_timeout=5000')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        INSERT OR IGNORE INTO metadata VALUES('schema_version','1');
        CREATE TABLE IF NOT EXISTS iterations(id TEXT PRIMARY KEY, product TEXT NOT NULL, record TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT, event TEXT NOT NULL, time TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS owners(product TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES iterations(id));
        CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, run TEXT NOT NULL REFERENCES iterations(id), target TEXT NOT NULL, kind TEXT NOT NULL, dedup TEXT UNIQUE NOT NULL, status TEXT NOT NULL, record TEXT NOT NULL);
        ''')
        self.db.commit()
        if self.db.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()[0] != '1':
            raise WorkbenchError('schema_unsupported', 'Unsupported state schema')

    def close(self):
        self.db.close()

    @contextlib.contextmanager
    def transaction(self):
        try:
            self.db.execute('BEGIN IMMEDIATE')
            yield
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    @contextlib.contextmanager
    def lock(self, name):
        private_dir(confined(self.root, 'state/locks'))
        path = confined(self.root, 'state/locks/' + digest(name) + '.lock')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise WorkbenchError('locked', 'Another executor owns this workbench operation')
            yield
        finally:
            os.close(fd)

    def audit(self, run, event, data):
        scan_sensitive(data)
        self.db.execute('INSERT INTO audit(run,event,time,data) VALUES(?,?,?,?)', (run, event, now(), json.dumps(data, ensure_ascii=False)))

    def put(self, run):
        scan_sensitive(run)
        run['updated_at'] = now()
        self.db.execute('INSERT INTO iterations VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record', (run['id'], run['product'], json.dumps(run, ensure_ascii=False)))

    def get(self, run_id):
        row = self.db.execute('SELECT record FROM iterations WHERE id=?', (run_id,)).fetchone()
        if not row:
            raise WorkbenchError('iteration_unknown', 'Iteration does not exist')
        return json.loads(row[0])

    def all(self, product=None):
        query = 'SELECT record FROM iterations' + (' WHERE product=?' if product else '')
        return [json.loads(row[0]) for row in self.db.execute(query, (product,) if product else ())]

    def claim(self, run):
        row = self.db.execute('SELECT run FROM owners WHERE product=?', (run['product'],)).fetchone()
        if row and row[0] != run['id']:
            raise WorkbenchError('product_owned', 'Another approved iteration owns this product')
        self.db.execute('INSERT OR IGNORE INTO owners VALUES(?,?)', (run['product'], run['id']))

    def action(self, action_id):
        row = self.db.execute('SELECT record FROM actions WHERE id=?', (action_id,)).fetchone()
        if not row:
            raise WorkbenchError('action_unknown', 'External action does not exist')
        return json.loads(row[0])

    def actions(self, run_id):
        return [json.loads(row[0]) for row in self.db.execute('SELECT record FROM actions WHERE run=?', (run_id,))]

    def unresolved(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT record FROM actions WHERE status IN ('running','uncertain')")]

    def find_action(self, key):
        row = self.db.execute('SELECT record FROM actions WHERE dedup=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put_action(self, item):
        scan_sensitive(item)
        self.db.execute('INSERT INTO actions VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,record=excluded.record', (item['id'], item['run'], item['target'], item['kind'], item['dedup'], item['status'], json.dumps(item, ensure_ascii=False)))
