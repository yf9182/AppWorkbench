"""Read-only loopback dashboard with explicit secret-free projections."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

from .errors import WorkbenchError
from .registry import Registry
from .security import now, safe_json, scan_sensitive, write_json, private_write

HTML = '''<!doctype html><html lang="zh"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AppWorkbench</title><style>body{font:16px system-ui;margin:32px;background:#f5f7fa;color:#172133}h1{font-size:28px}.card{background:white;padding:20px;border-radius:12px;margin:16px 0}pre{white-space:pre-wrap}small{color:#667}</style><h1>AppWorkbench</h1><small>只读本机进度 · 操作请回到 Codex 对话</small><main id="root"></main><script>fetch('/api/status').then(r=>r.json()).then(v=>{for(const p of v.products){const c=document.createElement('section');c.className='card';const h=document.createElement('h2');h.textContent=p.name;c.append(h);const g=document.createElement('p');g.textContent='目标：'+(p.goal||'待确认')+' · '+p.category;c.append(g);for(const r of v.iterations.filter(x=>x.product===p.id)){const a=document.createElement('pre');a.textContent=r.id+' · '+r.phase+(r.paused?' · 已暂停':'')+'\\n'+JSON.stringify(r.targets,null,2);c.append(a)}document.getElementById('root').append(c)}}).catch(()=>{document.getElementById('root').textContent='读取状态失败'})</script></html>'''


def _text(value):
    return safe_json(value) if isinstance(value, str) else None


def projection(root):
    root = Path(root).expanduser()
    if root.is_symlink():
        raise WorkbenchError('unsafe_path', 'Dashboard root cannot be a symlink')
    products = []
    for p in Registry(root).all():
        workflow = p.get('workflow', {})
        products.append({'id': _text(p.get('id')), 'name': _text(p.get('name')), 'goal': _text(workflow.get('goal')), 'category': _text(workflow.get('category')),
                         'targets': [{'id': _text(t.get('id')), 'kind': _text(t.get('kind')), 'depends_on': [_text(x) for x in t.get('depends_on', [])]} for t in workflow.get('targets', [])]})
    iterations = []
    path = root / 'state/workbench.sqlite'
    if path.is_symlink() or path.parent.is_symlink():
        raise WorkbenchError('unsafe_path', 'Dashboard state cannot be a symlink')
    if path.exists():
        connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
        try:
            for row in connection.execute('SELECT record FROM iterations'):
                r = json.loads(row[0])
                targets = []
                for target in r.get('targets', []):
                    checks = r.get('checks', {}).get(target, {})
                    targets.append({'id': _text(target), 'checks': [{'name': _text(k), 'status': _text(v.get('status'))} for k, v in checks.items()], 'human_acceptance': _text(r.get('acceptances', {}).get(target, {}).get('status', 'pending'))})
                actions = []
                for entry in connection.execute('SELECT record FROM actions WHERE run=?', (r['id'],)):
                    a = json.loads(entry[0]); actions.append({k: _text(a.get(k)) for k in ('id', 'target', 'kind', 'status')})
                iterations.append({'id': _text(r.get('id')), 'product': _text(r.get('product')), 'phase': _text(r.get('phase')), 'paused': r.get('paused') is True, 'revision': r.get('revision') if isinstance(r.get('revision'), int) else None,
                                   'updated_at': _text(r.get('updated_at')), 'targets': targets, 'reviews': [{'repository': _text(k), 'status': _text(v.get('status')), 'commit': _text(v.get('commit'))} for k,v in r.get('reviews', {}).items()],
                                   'evidence': [{'id': _text(e.get('id')), 'source': _text(e.get('source')), 'observed_at': _text(e.get('observed_at'))} for e in r.get('evidence', [])], 'actions': actions})
        finally:
            connection.close()
    value = safe_json({'schema_version': 1, 'generated_at': now(), 'read_only': True, 'products': products, 'iterations': iterations})
    scan_sensitive(value)
    return value


def export(root, output):
    output = Path(output).expanduser()
    if output.is_symlink() or any(x.is_symlink() for x in output.parents):
        raise WorkbenchError('unsafe_path', 'Export paths cannot be symlinks')
    data = projection(root)
    write_json(output / 'status.json', data)
    private_write(output / 'index.html', HTML.replace("fetch('/api/status')", "fetch('status.json')"))
    return {'directory': str(output.absolute()), 'products': len(data['products']), 'iterations': len(data['iterations']), 'read_only': True}


def handler(root):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
        def do_GET(self):
            expected_hosts = {'127.0.0.1:' + str(self.server.server_port), 'localhost:' + str(self.server.server_port)}
            if self.headers.get('Host') not in expected_hosts:
                self.send_error(403, 'Loopback host required'); return
            route = urlsplit(self.path).path
            try:
                if route in ('/', '/index.html'):
                    body, content = HTML.encode(), 'text/html; charset=utf-8'
                elif route == '/api/status':
                    body, content = json.dumps(projection(root), ensure_ascii=False).encode(), 'application/json; charset=utf-8'
                else:
                    self.send_error(404); return
                self.send_response(200)
                self.send_header('Content-Type', content)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
                self.end_headers(); self.wfile.write(body)
            except Exception:
                self.send_error(503, 'State unavailable')
        def do_POST(self):
            self.send_error(405, 'Read-only dashboard')
        do_PUT = do_POST
        do_DELETE = do_POST
        do_PATCH = do_POST
    return Handler


def serve(root, host='127.0.0.1', port=8765):
    if host not in ('127.0.0.1', 'localhost'):
        raise WorkbenchError('loopback_required', 'Dashboard must bind to IPv4 loopback')
    server = ThreadingHTTPServer(('127.0.0.1', port), handler(root))
    try:
        server.serve_forever()
    finally:
        server.server_close()
