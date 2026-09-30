"""Authenticated private runtime migration; platform credentials stay separate."""
import base64
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sqlite3
import tempfile
import zipfile

from .errors import WorkbenchError
from .security import confined, now, private_dir, private_write, read_json, scan_sensitive, sha256_file

MAGIC = b'APPWORKBENCH-STATE-1\n'
MAX_BYTES = 256 * 1024 * 1024
INSTRUCTIONS = '''# AppWorkbench state migration

This archive contains product configuration, SQLite state and run evidence, not platform credentials.
Restore the credential bundle separately using wb-credentials. Keep the key separate from the archive.
Clone AppWorkbench and restore to a new private directory. Revalidate repository local paths,
GitHub/Codex/Xcode sessions, credentials, signing and remote target identity on the destination.
Do not retry uncertain external actions before authenticated remote reconciliation.
Human approvals and history are preserved; restored history does not prove new-machine readiness.
'''


def _plain_path(path):
    path = Path(path).expanduser().absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise WorkbenchError('unsafe_path', 'Migration paths cannot be symlinks')
    return path


def _new_path(path):
    path = _plain_path(path)
    if path.exists():
        raise WorkbenchError('destination_exists', 'Migration destination already exists')
    return path


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError:
        raise WorkbenchError('crypto_unavailable', 'Use the bundled Python runtime with cryptography')


def _key(path):
    path = _plain_path(path)
    if not path.is_file() or path.stat().st_size > 1024 or path.stat().st_mode & 0o077:
        raise WorkbenchError('key_invalid', 'Migration key must be a private regular file')
    try:
        value = base64.b64decode(path.read_bytes().strip(), validate=True)
    except ValueError:
        raise WorkbenchError('key_invalid', 'Migration key format is invalid')
    if len(value) != 32:
        raise WorkbenchError('key_invalid', 'Migration key length is invalid')
    return value


def backup(root, output, key_file):
    root = _plain_path(root)
    output, key_file = _new_path(output), _new_path(key_file)
    if output == key_file or key_file.is_relative_to(root):
        raise WorkbenchError('unsafe_path', 'Keep migration key outside the runtime root and archive')
    aes = _aes()
    payload = io.BytesIO()
    with tempfile.TemporaryDirectory(prefix='wb-snapshot-') as tmp:
        files = []
        products = confined(root, 'products.json')
        if products.exists():
            scan_sensitive(read_json(products))
            files.append(('products.json', products))
        database = confined(root, 'state/workbench.sqlite')
        if database.exists():
            snapshot = Path(tmp) / 'workbench.sqlite'
            source = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
            target = sqlite3.connect(snapshot)
            try:
                source.backup(target)
            finally:
                target.close(); source.close()
            os.chmod(snapshot, 0o600)
            files.append(('state/workbench.sqlite', snapshot))
        for directory in ('runs',):
            folder = confined(root, directory)
            if folder.exists():
                for path in sorted(folder.rglob('*')):
                    confined(root, str(path.relative_to(root)))
                    if path.is_file():
                        files.append((path.relative_to(root).as_posix(), path))
        if len(files) > 10000 or sum(p.stat().st_size for _, p in files) > MAX_BYTES:
            raise WorkbenchError('backup_too_large', 'Runtime archive exceeds bounded migration size')
        with zipfile.ZipFile(payload, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, path in files:
                value = path.read_bytes()
                if name != 'state/workbench.sqlite':
                    scan_sensitive(value)
                archive.writestr(name, value)
            archive.writestr('MIGRATION.md', INSTRUCTIONS)
            archive.writestr('migration.json', json.dumps({'schema_version': 1, 'created_at': now(), 'credentials_included': False, 'source_root': str(root)}))
    key, nonce = os.urandom(32), os.urandom(12)
    encoded = MAGIC + nonce + aes(key).encrypt(nonce, payload.getvalue(), MAGIC)
    private_write(key_file, base64.b64encode(key) + b'\n')
    try:
        private_write(output, encoded)
    except Exception:
        key_file.unlink()
        raise
    return {'archive': str(output), 'key_file': str(key_file), 'files': len(files), 'sha256': sha256_file(output), 'credentials_included': False}


def restore(input, key_file, destination):
    source, destination = _plain_path(input), _new_path(destination)
    if not source.is_file() or source.stat().st_size > MAX_BYTES + 1024 * 1024:
        raise WorkbenchError('archive_invalid', 'Expected a bounded encrypted archive')
    data = source.read_bytes()
    try:
        if not data.startswith(MAGIC):
            raise ValueError()
        payload = _aes()(_key(key_file)).decrypt(data[len(MAGIC):len(MAGIC)+12], data[len(MAGIC)+12:], MAGIC)
    except WorkbenchError:
        raise
    except Exception:
        raise WorkbenchError('archive_authentication_failed', 'Archive authentication failed')
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            if len(infos) > 10000 or sum(i.file_size for i in infos) > MAX_BYTES:
                raise ValueError()
            names = set()
            for info in infos:
                name = PurePosixPath(info.filename)
                mode = info.external_attr >> 16
                if name.is_absolute() or '..' in name.parts or '\\' in info.filename or info.filename in names or (mode & 0o170000) == 0o120000:
                    raise ValueError()
                if str(name) != info.filename or not name.parts or (name.parts[0] not in {'products.json', 'state', 'runs', 'MIGRATION.md', 'migration.json'}):
                    raise ValueError()
                if name.parts[0] in {'products.json', 'MIGRATION.md', 'migration.json'} and len(name.parts) != 1:
                    raise ValueError()
                if name.parts[0] == 'state' and info.filename != 'state/workbench.sqlite':
                    raise ValueError()
                names.add(info.filename)
            contents = [(i.filename, archive.read(i)) for i in infos if not i.is_dir()]
            metadata = json.loads(dict(contents)['migration.json'])
            if metadata.get('schema_version') != 1 or metadata.get('credentials_included') is not False:
                raise ValueError()
    except Exception:
        raise WorkbenchError('archive_invalid', 'Archive structure is invalid')
    private_dir(destination.parent)
    staging = Path(tempfile.mkdtemp(prefix='.wb-restore-', dir=destination.parent))
    try:
        for name, value in contents:
            private_write(confined(staging, name), value)
        db = staging / 'state/workbench.sqlite'
        if db.exists():
            connection = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)
            try:
                if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise WorkbenchError('archive_invalid', 'Restored state database is invalid')
            finally:
                connection.close()
        if destination.exists() or destination.is_symlink():
            raise WorkbenchError('destination_exists', 'Migration destination appeared during restore')
        os.rename(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return {'destination': str(destination), 'files': len(contents), 'credentials_included': False, 'revalidation_required': ['repository_paths', 'credentials', 'platform_sessions', 'signing', 'remote_actions'], 'instructions': str(destination / 'MIGRATION.md')}
