"""Read-only loopback dashboard with explicit secret-free projections."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
from urllib.parse import urlsplit

from .errors import WorkbenchError
from .registry import Registry
from .security import confined, read_json, now, safe_json, scan_sensitive, write_json, private_write

HTML = '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>AppWorkbench</title><style>\n:root{color-scheme:light;--ink:#172b3e;--muted:#6b7d8e;--line:#e1e9ee;--accent:#167b74}*{box-sizing:border-box}body{font:15px system-ui,-apple-system,sans-serif;margin:0;background:#f3f6f8;color:var(--ink)}header{background:#fff;border-bottom:1px solid var(--line);padding:25px max(24px,calc((100vw - 1120px)/2));display:flex;align-items:center;gap:15px}.logo{background:var(--ink);color:white;padding:11px;border-radius:12px;font-weight:800}h1{font-size:23px;margin:0}header p{margin:5px 0 0;color:var(--muted)}main{max-width:1120px;margin:32px auto;padding:0 24px}.summary{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:25px}.summary span{padding:12px 16px;background:white;border:1px solid var(--line);border-radius:10px}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:15px}input{border:1px solid var(--line);padding:12px 14px;border-radius:9px;min-width:220px;font:inherit}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:24px}h2{font-size:19px;margin:0 0 12px}.muted{color:var(--muted);line-height:1.7}.pill{display:inline-block;font-size:12px;padding:4px 8px;border-radius:6px;background:#edf5f4;color:var(--accent);margin:0 7px 7px 0}.warn{background:#fff4df;color:#957029}.run{margin-top:18px;border-top:1px solid var(--line);padding-top:17px}.run h3{font-size:15px;margin:0 0 9px}.line{display:flex;justify-content:space-between;gap:10px;margin:8px 0}.small{font-size:12px;color:var(--muted)}footer{margin:28px 0;color:var(--muted);font-size:13px}.empty{padding:14px 0;color:var(--muted)}@media(max-width:700px){.grid{grid-template-columns:1fr}.toolbar{align-items:flex-start;flex-direction:column}header{padding:22px}main{padding:0 18px}} </style>\n<header><div class="logo">AW</div><div><h1>AppWorkbench</h1><p>产品迭代 · 交付证据 · 验收反馈</p></div></header><main><div class="summary" id="summary"></div><div class="toolbar"><strong>产品与版本</strong><input id="search" aria-label="查找产品" placeholder="查找产品名称"></div><div id="root" class="grid"></div><footer>只读本机工作台。规划、确认和执行请回到 Codex 对话。TestFlight 上传与自动测试不能代替真人验收。</footer></main><script>\nconst labels={awaiting_plan_confirmation:\'待确认计划\',approved:\'计划已确认\',implementing:\'实现中\',delivering:\'交付中\',delivery_attention:\'交付需处理\',feedback_pending:\'待验收反馈\',accepted:\'已验收\',pending:\'待完成\',passed:\'通过\',failed:\'失败\',succeeded:\'完成\',uncertain:\'待核对远端\',unverified:\'未验证\',ready:\'已读取\',partial:\'部分可用\',product:\'产品\',shared_service:\'共享服务\',tool:\'工具\',library:\'组件\'};\nconst node=(tag,text,cls)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;if(cls)e.className=cls;return e};\nlet state;function render(){const root=document.getElementById(\'root\');root.replaceChildren();const q=document.getElementById(\'search\').value.toLowerCase();for(const p of state.products.filter(p=>p.name.toLowerCase().includes(q))){const c=node(\'section\',undefined,\'card\');c.append(node(\'h2\',p.name),node(\'span\',labels[p.category]||\'待分类\',\'pill\'),node(\'p\',\'运营目标：\'+(p.goal||\'待你设置\'),\'muted\'));const data=p.data_sources||[];c.append(node(\'div\',data.length?\'最近调查数据\':\'尚未采集数据\',\'small\'));for(const d of data)c.append(node(\'span\',d.source+\' · \'+(labels[d.status]||d.status),\'pill \'+(d.status===\'ready\'?\'\':\'warn\')));const runs=state.iterations.filter(r=>r.product===p.id);if(!runs.length)c.append(node(\'p\',\'尚无迭代计划\',\'empty\'));for(const r of runs){const box=node(\'div\',undefined,\'run\');box.append(node(\'h3\',(labels[r.phase]||r.phase)+(r.paused?\' · 已暂停\':\'\')),node(\'div\',\'计划修订 \'+r.revision+\' · \'+r.id,\'small\'));for(const t of r.targets){const line=node(\'div\',undefined,\'line\');line.append(node(\'strong\',t.id),node(\'span\',\'验收：\'+(labels[t.human_acceptance]||t.human_acceptance),\'small\'));box.append(line);for(const ch of t.checks)box.append(node(\'span\',ch.name+\' · \'+(labels[ch.status]||ch.status),\'pill\'));}for(const review of r.reviews)box.append(node(\'div\',review.repository+\' · 独立评审 \'+(labels[review.status]||review.status),\'small\'));for(const a of r.actions)box.append(node(\'div\',a.target+\' / \'+a.kind+\' · \'+(labels[a.status]||a.status),\'small\'));box.append(node(\'p\',\'证据 \'+r.evidence.length+\' 项 · \'+(r.phase===\'awaiting_plan_confirmation\'?\'下一步：在 Codex 确认具体计划\':\'下一步：查看交付记录与未完成验收\'),\'small\'));c.append(box)}c.append(node(\'div\',\'上线效果：尚未发起版本效果评估\',\'small\'));root.append(c)}}\nfetch(\'/api/status\').then(r=>r.json()).then(v=>{state=v;const s=document.getElementById(\'summary\');for(const text of [v.products.length+\' 个登记项目\',v.iterations.length+\' 个迭代\',v.iterations.filter(r=>r.phase===\'awaiting_plan_confirmation\').length+\' 份计划待确认\'])s.append(node(\'span\',text));render();document.getElementById(\'search\').addEventListener(\'input\',render)}).catch(()=>{document.getElementById(\'root\').textContent=\'状态暂不可用，请在 Codex 查看状态\'});</script></html>'


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
    for product in products:
        product['data_sources'] = []
        directory = confined(root, 'assessments/' + product['id'])
        if directory.exists():
            candidates = sorted(directory.glob('*/data.json'), key=lambda p:p.stat().st_mtime, reverse=True)
            if candidates:
                data = read_json(confined(root, str(candidates[0].relative_to(root))))
                product['data_sources'] = [{k:_text(row.get(k)) for k in ('source', 'status', 'checked_at')} for row in data.get('sources', [])]
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
