"""Private files, bounded inputs and sanitized process/report output."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from .errors import WorkbenchError

SECRET_KEYS = {'private_key', 'api_token', 'access_token', 'refresh_token', 'authorization', 'password', 'secret_value', 'client_secret'}
SECRET_PATTERNS = [re.compile(r'-----BEGIN (?:[A-Z ]*?)PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]*?)PRIVATE KEY-----'), re.compile(r'\bcfat_[A-Za-z0-9_-]{20,}'), re.compile(r'\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}')]
_known_secrets = set()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def remember_secret(value):
    if isinstance(value, str) and len(value) >= 12:
        _known_secrets.add(value)

def redact_text(value):
    for secret in sorted(_known_secrets, key=len, reverse=True):
        value = value.replace(secret, '[REDACTED]')
    for pattern in SECRET_PATTERNS:
        value = pattern.sub('[REDACTED]', value)
    return value

def safe_json(value):
    if isinstance(value, dict):
        return {str(k): '[REDACTED]' if str(k).lower() in SECRET_KEYS else safe_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe_json(x) for x in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

def scan_sensitive(value):
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            return  # Binary build artifacts are separately validated by their adapter.
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    if redact_text(value) != value:
        raise WorkbenchError('secret_refused', 'Sensitive material cannot enter workbench evidence or output')
    try:
        parsed = json.loads(value)
    except (ValueError, TypeError):
        return
    if safe_json(parsed) != parsed:
        raise WorkbenchError('secret_refused', 'Credential values cannot enter workbench records')

def private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise WorkbenchError('unsafe_path', 'Managed directories cannot be symlinks')
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path

def confined(root, relative):
    root = Path(root).resolve()
    name = Path(relative)
    if name.is_absolute() or '..' in name.parts:
        raise WorkbenchError('unsafe_path', 'Expected a relative managed path')
    path = root / name
    if not path.resolve().is_relative_to(root):
        raise WorkbenchError('unsafe_path', 'Path escapes the managed directory')
    p = path
    while p != root:
        if p.is_symlink():
            raise WorkbenchError('unsafe_path', 'Managed paths cannot be symlinks')
        p = p.parent
    return path

def private_write(path, data):
    path = Path(path)
    private_dir(path.parent)
    if path.is_symlink():
        raise WorkbenchError('unsafe_path', 'Destination cannot be a symlink')
    if isinstance(data, str):
        data = data.encode()
    fd, temporary = tempfile.mkstemp(prefix='.wb-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def write_json(path, value):
    scan_sensitive(value)
    private_write(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def read_json(path, max_bytes=8 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > max_bytes:
        raise WorkbenchError('invalid_file', 'Expected a bounded regular JSON file')
    try:
        return json.loads(path.read_text())
    except (ValueError, UnicodeError):
        raise WorkbenchError('invalid_json', 'JSON file is malformed')

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

def credential_path(root, credential_id):
    root = Path(root)
    manifest = read_json(root / 'manifest.json')
    rows = manifest.get('credentials', [])
    item = rows.get(credential_id) if isinstance(rows, dict) else next((x for x in rows if x['id'] == credential_id), None)
    if not item or not item.get('file'):
        raise WorkbenchError('credential_missing', 'Credential reference has no local file')
    path = confined(root, item['file'])
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise WorkbenchError('credential_permissions', 'Credential file must exist and be private')
    if path.suffix in {'.txt', '.p8', '.pem'}:
        remember_secret(path.read_text().strip())
    elif path.suffix == '.json':
        for k, v in read_json(path).items():
            if k in SECRET_KEYS:
                remember_secret(v)
    return path
