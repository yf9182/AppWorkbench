import base64
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
import zipfile

from appworkbench import migration, dashboard
from appworkbench.errors import WorkbenchError
from appworkbench.store import Store
from appworkbench.security import write_json
from http.server import ThreadingHTTPServer

class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name).resolve(); self.root=self.base/'runtime'; self.root.mkdir()
        write_json(self.root/'products.json', {'products':[{'id':'p','name':'Product','workflow':{'goal':'retention','category':'product','targets':[]},'credential_refs':{'google':'credential-id'},'private_note':'not-for-dashboard'}]})
        self.store=Store(self.root)
        with self.store.transaction():
            self.store.put({'id':'r','product':'p','phase':'awaiting_plan_confirmation','targets':[],'paused':False,'plan':'private business idea','evidence':[{'id':'e','source':'ga4','observed_at':'date','data':{'raw_provider':'hidden'}}]})
        write_json(self.root/'runs/r/report.json', {'status':'partial'})
        (self.root/'secrets').mkdir(); (self.root/'secrets/token.txt').write_text('never-include-platform-token')
    def tearDown(self):
        self.store.close(); self.tmp.cleanup()
    def pack(self):
        a=self.base/'state.awb'; k=self.base/'key'; migration.backup(self.root,a,k); return a,k
    def test_snapshot_roundtrip_excludes_credentials(self):
        a,k=self.pack(); dest=self.base/'restored'; result=migration.restore(a,k,dest)
        self.assertFalse(result['credentials_included']); self.assertFalse((dest/'secrets').exists())
        self.assertEqual((dest/'runs/r/report.json').read_bytes(),(self.root/'runs/r/report.json').read_bytes())
        db=sqlite3.connect(dest/'state/workbench.sqlite'); self.assertEqual(db.execute('select count(*) from iterations').fetchone()[0],1); db.close()
        self.assertEqual((dest/'state/workbench.sqlite').stat().st_mode & 0o777,0o600)
        self.assertEqual(dest.stat().st_mode & 0o777,0o700)
        with self.assertRaises(WorkbenchError): migration.restore(a,k,dest)
    def test_restore_can_merge_separate_credentials_without_overwriting_products(self):
        a,k=self.pack();credentials=self.base/'credentials';credentials.mkdir();(credentials/'secrets').mkdir();token=credentials/'secrets/provider.txt';token.write_text('test-value-for-private-transfer');token.chmod(0o600)
        write_json(credentials/'manifest.json',{'credentials':{'test':{'file':'secrets/provider.txt'}}});write_json(credentials/'products.json',{'products':[]})
        result=migration.restore(a,k,self.base/'merged',credentials);self.assertTrue(result['credentials_included']);self.assertEqual((self.base/'merged/secrets/provider.txt').read_bytes(),token.read_bytes());self.assertEqual(json.loads((self.base/'merged/products.json').read_text())['products'][0]['id'],'p')
        token.chmod(0o644)
        with self.assertRaises(WorkbenchError):migration.restore(a,k,self.base/'invalid-merge',credentials)
        self.assertFalse((self.base/'invalid-merge').exists())
    def test_assessment_reports_are_migrated_without_raw_dashboard_projection(self):
        write_json(self.root/'assessments/p/snapshot/data.json',{'sources':[{'source':'ga4','status':'partial','checked_at':'time','data':{'raw':'private-metric'}}]})
        a,k=self.pack();dest=self.base/'restored-reports';migration.restore(a,k,dest);self.assertTrue((dest/'assessments/p/snapshot/data.json').is_file());projection=dashboard.projection(dest);self.assertEqual(projection['products'][0]['data_sources'][0]['status'],'partial');self.assertNotIn('private-metric',json.dumps(projection))
    def test_tamper_wrong_key_and_symlink(self):
        a,k=self.pack(); original=a.read_bytes(); data=bytearray(original); data[-1]^=1; a.write_bytes(data)
        with self.assertRaises(WorkbenchError): migration.restore(a,k,self.base/'tampered')
        self.assertFalse((self.base/'tampered').exists())
        a.write_bytes(original)
        other=self.base/'other'; other.write_bytes(base64.b64encode(os.urandom(32))); other.chmod(0o600)
        with self.assertRaises(WorkbenchError): migration.restore(a,other,self.base/'wrong')
        link=self.root/'runs/link'; link.symlink_to(self.base/'outside')
        with self.assertRaises(WorkbenchError): migration.backup(self.root,self.base/'second',self.base/'second-key')
    def test_authenticated_traversal_rejected(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        a,k=self.pack(); payload=io.BytesIO()
        with zipfile.ZipFile(payload,'w') as z:
            z.writestr('../outside','unsafe'); z.writestr('migration.json','{"schema_version":1,"credentials_included":false}')
        nonce=os.urandom(12); a.write_bytes(migration.MAGIC+nonce+AESGCM(base64.b64decode(k.read_bytes())).encrypt(nonce,payload.getvalue(),migration.MAGIC))
        with self.assertRaises(WorkbenchError): migration.restore(a,k,self.base/'bad')
        self.assertFalse((self.base/'outside').exists()); self.assertFalse((self.base/'bad').exists())
    def test_projection_and_export_do_not_leak(self):
        before=self.store.path.read_bytes(); data=dashboard.projection(self.root); text=json.dumps(data)
        for secret in ('never-include-platform-token','private business idea','not-for-dashboard','raw_provider','credential-id'): self.assertNotIn(secret,text)
        self.assertEqual(data['products'][0]['goal'],'retention'); self.assertEqual(before,self.store.path.read_bytes())
        dest=self.base/'export'; dashboard.export(self.root,dest); self.assertEqual(json.loads((dest/'status.json').read_text())['iterations'][0]['phase'],'awaiting_plan_confirmation')
    def test_local_routes_are_read_only(self):
        with self.assertRaises(WorkbenchError): dashboard.serve(self.root,'0.0.0.0',0)
        server=ThreadingHTTPServer(('127.0.0.1',0),dashboard.handler(self.root)); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        try:
            self.assertTrue(json.load(urllib.request.urlopen(base+'/api/status'))['read_only'])
            for route in ('/secrets/token.txt','/../products.json'):
                with self.assertRaises(urllib.error.HTTPError) as err: urllib.request.urlopen(base+route)
                self.assertEqual(err.exception.code,404)
            with self.assertRaises(urllib.error.HTTPError) as err: urllib.request.urlopen(urllib.request.Request(base+'/api/status',data=b'{}',method='POST'))
            self.assertEqual(err.exception.code,405)
            with self.assertRaises(urllib.error.HTTPError) as err: urllib.request.urlopen(urllib.request.Request(base+'/api/status',headers={'Host':'attacker.example'}))
            self.assertEqual(err.exception.code,403)
        finally:
            server.shutdown(); server.server_close(); thread.join()
