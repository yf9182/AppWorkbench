"""Control-plane regression tests; fake remote transport proves no production action."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from appworkbench.engine import Engine
from appworkbench.errors import WorkbenchError
from appworkbench.security import digest, read_json, safe_json, scan_sensitive, sha256_file, write_json

class Transport:
    def __init__(self):self.calls=[];self.outcomes={}
    def deployment_preflight(self,*args):return {'authenticated':True,'rollback_version_id':'11111111-1111-1111-1111-111111111111'}
    def execute_action(self, action, product, root, target, candidate, parameters):
        self.calls.append((action,target['id'],parameters))
        outcome=self.outcomes.get((action,target['id']),{'status':'succeeded','authenticated':True})
        if isinstance(outcome,Exception):raise outcome
        return outcome
    def collect_product(self,*args):return {'sources':[{'source':'apple','status':'unverified','reason':'Revenue unavailable','data':None},{'source':'ga4','status':'succeeded','data':{'activeUsers':2}}]}

class Core(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name);self.root=self.base/'private';self.repo=self.base/'Repo';self.repo.mkdir()
        self.git('init','-q');self.git('config','user.name','Implementer');self.git('config','user.email','test@example.invalid');self.git('remote','add','origin','https://github.com/owner/Repo.git')
        (self.repo/'source.txt').write_text('initial\n');self.git('add','.');self.git('commit','-qm','Initial')
        self.transport=Transport();self.engine=Engine(self.root,self.transport)
        target={'id':'web','repository':'Repo','kind':'web','checks':[{'id':'tests','argv':['python3','-c','print(1)']}],'required_checks':['tests'],'depends_on':[],'rollback_policy':'previous_active_version'}
        self.product={'id':'product','name':'Product','repositories':[{'owner':'owner','name':'Repo','local_path':str(self.repo)}],'workflow':{'targets':[target]}}
        self.engine.registry.register(self.product)
        self.plan=self.base/'plan.md';self.plan.write_text('A useful real version: improve the onboarding experience with explicit acceptance criteria.\n')
        self.run=self.engine.create('product',self.plan)['id'];self.sha=self.git('rev-parse','HEAD');self.value={'repository':'Repo','commit':self.sha,'local_path':str(self.repo),'author':'implementer'}
    def tearDown(self):self.engine.store.close();self.tmp.cleanup()
    def git(self,*args):return subprocess.run(['git','-C',str(self.repo),*args],capture_output=True,text=True,check=True).stdout.strip()
    def error(self,code,call,*args,**kwargs):
        with self.assertRaises(WorkbenchError) as result:call(*args,**kwargs)
        self.assertEqual(result.exception.code,code)
    def approved(self):self.engine.approve(self.run,'human-yf','Execute this exact version plan');self.engine.candidate(self.run,self.value)
    def gated(self):
        self.approved();self.engine.review(self.run,{'repository':'Repo','commit':self.sha,'reviewer':'independent','status':'passed','findings':[]});self.engine.check(self.run,'web')
    def deliver(self,action):return self.engine.deliver(self.run,'web',action)
    def test_unapproved_plan_cannot_develop(self):
        self.error('plan_unapproved',self.engine.candidate,self.run,self.value);self.assertEqual(self.transport.calls,[])
    def test_plan_tamper_and_revision_clear_confirmation(self):
        self.approved();p=self.root/self.engine.status(self.run)['plan_path'];p.write_text('tampered')
        self.error('plan_changed',self.deliver,'pr');self.engine.revise(self.run,self.plan);self.error('plan_unapproved',self.engine.candidate,self.run,self.value)
    def test_ai_cannot_attest_human_approval(self):self.error('human_confirmation_required',self.engine.approve,self.run,'codex','approved')
    def test_single_product_executor(self):
        self.approved();other=self.engine.create('product',self.plan)['id'];self.error('product_owned',self.engine.approve,other,'human-yf','Execute plan')
    def test_pause_then_resume_preserves_candidate(self):
        self.approved();self.engine.control(self.run,'pause');self.error('paused',self.deliver,'pr');self.engine.control(self.run,'resume');self.assertEqual(self.engine.status(self.run)['candidates']['Repo']['commit'],self.sha)
    def test_identity_mismatch_refused(self):
        self.engine.approve(self.run,'human-yf','Execute plan');self.git('remote','set-url','origin','https://github.com/owner/Other.git');self.error('identity_mismatch',self.engine.candidate,self.run,self.value)
    def test_independent_reviewer_required(self):
        self.approved();self.error('independent_review_required',self.engine.review,self.run,{'repository':'Repo','commit':self.sha,'reviewer':'implementer','status':'passed'})
    def test_review_blocking_findings_not_passed(self):
        self.approved();self.error('review_blocking_findings',self.engine.review,self.run,{'repository':'Repo','commit':self.sha,'reviewer':'reviewer','status':'passed','findings':[{'priority':'P1'}]})
    def test_gate_and_deduplication(self):
        self.gated();first=self.deliver('pr');second=self.deliver('pr');self.assertEqual(first['id'],second['id']);self.assertTrue(second['deduplicated']);self.assertEqual(sum(a[0]=='pr' for a in self.transport.calls),1)
    def test_review_evidence_tampering_refused(self):
        self.gated();ref=self.engine.status(self.run)['reviews']['Repo']['evidence'];(self.root/ref['path']).write_text('changed');self.error('evidence_changed',self.deliver,'pr')
    def test_candidate_change_invalidates_tests_review(self):
        self.gated();(self.repo/'source.txt').write_text('change\n');self.git('add','.');self.git('commit','-qm','Change');v={**self.value,'commit':self.git('rev-parse','HEAD')};self.engine.candidate(self.run,v)
        self.assertEqual(self.engine.status(self.run)['reviews'],{});self.error('review_required',self.deliver,'pr')
    def test_config_change_blocks_delivery(self):
        self.gated();p=copy.deepcopy(self.product);p['workflow']['goal']='revenue';self.engine.registry.register(p);self.error('configuration_changed',self.deliver,'pr')
    def test_timeout_intent_requires_authenticated_reconcile(self):
        self.gated();self.transport.outcomes[('pr','web')]=TimeoutError();item=self.deliver('pr');self.assertEqual(item['status'],'uncertain');self.error('action_uncertain',self.deliver,'pr')
        self.transport.outcomes[('reconcile','web')]={'status':'succeeded'};self.error('reconciliation_unverified',self.engine.reconcile,self.run,item['id'])
        self.transport.outcomes[('reconcile','web')]={'status':'succeeded','authenticated':True};self.engine.reconcile(self.run,item['id']);self.assertTrue(self.deliver('pr')['deduplicated'])
    def test_smoke_failure_rolls_back_and_cannot_accept(self):
        self.gated();self.deliver('pr');self.deliver('merge');self.deliver('deploy');self.transport.outcomes[('smoke','web')]={'status':'failed'};result=self.deliver('smoke');self.assertEqual(result['automatic_rollback']['status'],'succeeded')
        self.error('delivery_pending',self.engine.accept,self.run,{'actor':'human-yf','message':'tested','target':'web','commit':self.sha,'status':'passed','checks':{'core_path':'passed'}})
    def test_human_feedback_required_and_candidate_bound(self):
        self.gated();self.deliver('pr');self.deliver('merge');self.deliver('deploy');self.deliver('smoke')
        value={'actor':'human-yf','message':'Core path works on deployed version','target':'web','commit':self.sha,'status':'passed','checks':{'core_path':'passed'}}
        self.error('acceptance_mismatch',self.engine.accept,self.run,{**value,'commit':'a'*40});self.error('human_acceptance_required',self.engine.accept,self.run,{**value,'actor':'codex'});self.assertEqual(self.engine.accept(self.run,value)['phase'],'accepted')
    def test_no_store_submission(self):self.error('action_forbidden',self.deliver,'submit')
    def test_missing_revenue_is_unknown_and_collection_partial(self):
        data=self.engine.collect('product');self.assertIsNone(data['sources'][0]['data']);self.assertEqual(data['sources'][1]['status'],'succeeded')
    def test_secret_records_refused_and_output_redacted(self):
        secret='cfat_'+'x'*40;self.error('secret_refused',scan_sensitive,{'private_key':'secret'});self.error('secret_refused',scan_sensitive,secret);self.assertNotIn(secret,json.dumps(safe_json({'reason':secret})))
    def test_dependency_cycle_refused(self):
        p=copy.deepcopy(self.product);t=p['workflow']['targets'][0];other=copy.deepcopy(t);other['id']='backend';t['depends_on']=['backend'];other['depends_on']=['web'];p['workflow']['targets'].append(other);self.error('dependency_cycle',self.engine.registry.register,p)
    def test_deploy_requires_merged_pr(self):self.gated();self.error('merge_required',self.deliver,'deploy')
    def test_changed_artifact_refused(self):
        self.approved();ipa=self.base/'app.ipa';ipa.write_bytes(b'initial');value={**self.value,'artifact':{'path':str(ipa),'sha256':sha256_file(ipa)}};self.engine.candidate(self.run,value);ipa.write_bytes(b'changed');self.error('artifact_changed',self.engine.candidate,self.run,value)

if __name__=='__main__':unittest.main()
