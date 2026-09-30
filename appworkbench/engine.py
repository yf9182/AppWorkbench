"""Human-approved, evidence-bound iterations and recoverable deliveries."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

from .errors import WorkbenchError
from .registry import Registry, configuration_digest, identifier
from .security import confined, digest, now, private_dir, private_write, read_json, safe_json, scan_sensitive, sha256_file, write_json
from .store import Store

ACTIONS = {'pr', 'merge', 'deploy', 'smoke', 'rollback', 'archive', 'upload_tf', 'prepare_store'}
ACCEPTANCE_NAMES = {'installation': 'device_install', 'core_paths': 'core_path', 'existing_rights': 'existing_entitlements', 'metadata': 'metadata_review'}

def code_binding(candidate):
    value = copy.deepcopy(candidate)
    value.pop('artifact', None)
    return digest(value)

class Engine:
    def __init__(self, root, adapter=None):
        self.root = Path(root).expanduser().resolve()
        self.registry = Registry(self.root)
        self.store = Store(self.root)
        if adapter is None:
            from . import adapters
            adapter = adapters
        self.adapter = adapter

    def _run_path(self, run_id, name):
        identifier(run_id)
        return confined(self.root, 'runs/' + run_id + '/' + name)

    def _evidence(self, run, source, value=None, file=None, binding=None):
        evidence_id = uuid.uuid4().hex
        if file is not None:
            original = Path(file)
            if original.is_symlink() or not original.is_file() or original.stat().st_size > 16 * 1024 * 1024:
                raise WorkbenchError('evidence_invalid', 'Evidence must be a bounded regular file')
            data = original.read_bytes()
            suffix = original.suffix if original.suffix in {'.json', '.md', '.txt', '.png', '.jpg'} else '.bin'
        else:
            value = safe_json(value)
            data = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
            suffix = '.json'
        scan_sensitive(data)
        relative = 'runs/' + run['id'] + '/evidence/' + evidence_id + suffix
        path = confined(self.root, relative)
        private_write(path, data)
        result = {'id': evidence_id, 'path': relative, 'sha256': sha256_file(path), 'source': source, 'observed_at': now(), 'binding': binding or {}}
        run['evidence'].append(result)
        return result

    def _verify_evidence(self, reference):
        path = confined(self.root, reference['path'])
        if not path.is_file() or sha256_file(path) != reference['sha256']:
            raise WorkbenchError('evidence_changed', 'Recorded evidence is missing or its digest changed')

    def create(self, product_name, plan_file, targets=None):
        product = self.registry.get(product_name)
        self.registry.validate(product)
        path = Path(plan_file)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise WorkbenchError('plan_invalid', 'Plan must be a bounded regular document')
        body = path.read_bytes()
        scan_sensitive(body)
        if len(body.strip()) < 40:
            raise WorkbenchError('plan_invalid', 'A concrete version plan is required')
        selected = targets or [t['id'] for t in product.get('workflow', {}).get('targets', [])]
        for target in selected:
            self.registry.target(product, target)
        if len(set(selected)) != len(selected):
            raise WorkbenchError('target_invalid', 'Duplicate selected target')
        run = {'id': uuid.uuid4().hex[:16], 'product': product['id'], 'created_at': now(), 'phase': 'awaiting_plan_confirmation', 'paused': False, 'revision': 1, 'targets': selected, 'plan_sha256': '', 'configuration_sha256': configuration_digest(product), 'approval': None, 'candidates': {}, 'reviews': {}, 'checks': {}, 'acceptances': {}, 'evidence': [], 'revisions': []}
        private_write(self._run_path(run['id'], 'plan-1.md'), body)
        run['plan_sha256'] = sha256_file(self._run_path(run['id'], 'plan-1.md'))
        run['plan_path'] = 'runs/' + run['id'] + '/plan-1.md'
        run['revisions'].append({'revision': 1, 'sha256': run['plan_sha256'], 'targets': selected, 'created_at': now()})
        with self.store.transaction():
            self.store.put(run)
            self.store.audit(run['id'], 'plan_created', {'sha256': run['plan_sha256'], 'targets': selected})
        self.report(run['id'])
        return self.status(run['id'])

    def _approved(self, run):
        if run['paused']:
            raise WorkbenchError('paused', 'Iteration is paused')
        if not run.get('approval') or run['approval']['plan_sha256'] != run['plan_sha256']:
            raise WorkbenchError('plan_unapproved', 'This exact plan revision needs a real human confirmation')
        if sha256_file(confined(self.root, run['plan_path'])) != run['plan_sha256']:
            raise WorkbenchError('plan_changed', 'Approved plan document changed')
        if run.get('phase') in {'accepted', 'awaiting_manual_submission'}:
            raise WorkbenchError('iteration_complete', 'Accepted iteration needs new actual defect feedback or a new plan before further implementation')
        owner = self.store.db.execute('SELECT run FROM owners WHERE product=?', (run['product'],)).fetchone()
        if not owner or owner[0] != run['id']:
            raise WorkbenchError('product_owned', 'This iteration does not own product execution')
        product = self.registry.get(run['product'])
        self.registry.validate(product)
        if configuration_digest(product) != run['configuration_sha256']:
            raise WorkbenchError('configuration_changed', 'Product identity or workflow configuration changed; revise and reconfirm the plan')
        return product

    def approve(self, run_id, actor, message):
        if not actor.strip() or not message.strip() or actor.lower() in {'ai', 'agent', 'codex', 'coordinator'} or actor.startswith('/root'):
            raise WorkbenchError('human_confirmation_required', 'Record the actual human identity and instruction')
        scan_sensitive(message)
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            if run['paused']:
                raise WorkbenchError('paused', 'Iteration is paused')
            product = self.registry.get(run['product'])
            if configuration_digest(product) != run['configuration_sha256']:
                raise WorkbenchError('configuration_changed', 'Product configuration changed since the plan was created')
            if sha256_file(confined(self.root, run['plan_path'])) != run['plan_sha256']:
                raise WorkbenchError('plan_changed', 'Plan content changed; create a new revision')
            self.store.claim(run)
            run['approval'] = {'actor': actor, 'message': message, 'plan_sha256': run['plan_sha256'], 'revision': run['revision'], 'confirmed_at': now(), 'kind': 'human_instruction_attestation'}
            run['phase'] = 'approved'
            self.store.put(run)
            self.store.audit(run_id, 'human_plan_confirmed', run['approval'])
        self.report(run_id)
        return self.status(run_id)

    def revise(self, run_id, plan_file, targets=None):
        path = Path(plan_file)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise WorkbenchError('plan_invalid', 'Plan must be a bounded regular document')
        body = path.read_bytes()
        scan_sensitive(body)
        if len(body.strip()) < 40:
            raise WorkbenchError('plan_invalid', 'A concrete version plan is required')
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            if any(a['status'] in {'running', 'uncertain'} for a in self.store.actions(run_id)):
                raise WorkbenchError('action_unresolved', 'Reconcile pending external actions before revising')
            product = self.registry.get(run['product'])
            selected = run['targets'] if targets is None else targets
            for target in selected:
                self.registry.target(product, target)
            run['revision'] += 1
            run['targets'] = selected
            run['plan_path'] = 'runs/' + run_id + '/plan-' + str(run['revision']) + '.md'
            private_write(confined(self.root, run['plan_path']), body)
            run['plan_sha256'] = sha256_file(confined(self.root, run['plan_path']))
            run['configuration_sha256'] = configuration_digest(product)
            run['approval'] = None
            run['candidates'], run['reviews'], run['checks'], run['acceptances'] = {}, {}, {}, {}
            run['phase'] = 'awaiting_plan_confirmation'
            run['revisions'].append({'revision': run['revision'], 'sha256': run['plan_sha256'], 'targets': selected, 'created_at': now()})
            self.store.put(run)
            self.store.audit(run_id, 'plan_revised', {'revision': run['revision'], 'sha256': run['plan_sha256']})
        self.report(run_id)
        return self.status(run_id)

    def _repository(self, product, repository):
        hits = [r for r in product['repositories'] if repository in {r['name'], r['owner'] + '/' + r['name']}]
        if len(hits) != 1:
            raise WorkbenchError('repository_unknown', 'Candidate repository is not part of this product')
        return hits[0]

    def _workspace(self, product, candidate):
        repo = self._repository(product, candidate['repository'])
        path = Path(candidate['local_path']).expanduser()
        if path.is_symlink() or not path.is_dir():
            raise WorkbenchError('workspace_missing', 'Candidate checkout is missing or is a symlink')
        def git(*args):
            p = subprocess.run(['git', '-C', str(path), *args], capture_output=True, text=True, timeout=20)
            if p.returncode:
                raise WorkbenchError('git_failed', 'Cannot verify candidate checkout')
            return p.stdout.strip()
        origin = git('remote', 'get-url', 'origin')
        normalized = origin.removesuffix('.git').removesuffix('/')
        expected = repo['owner'] + '/' + repo['name']
        if normalized not in {'https://github.com/' + expected, 'git@github.com:' + expected, 'ssh://git@github.com/' + expected}:
            raise WorkbenchError('identity_mismatch', 'Checkout origin does not match the registered repository')
        if git('rev-parse', 'HEAD') != candidate['commit']:
            raise WorkbenchError('candidate_changed', 'Checkout HEAD changed since candidate registration')
        if git('status', '--porcelain'):
            raise WorkbenchError('workspace_dirty', 'Candidate checkout must be committed and clean')
        artifact = candidate.get('artifact')
        if artifact:
            artifact_path = Path(artifact['path'])
            if artifact_path.is_symlink() or not artifact_path.is_file() or sha256_file(artifact_path) != artifact['sha256']:
                raise WorkbenchError('artifact_changed', 'Candidate artifact is missing or changed')
        return repo

    def _dependent_targets(self, product, repository):
        targets = product.get('workflow', {}).get('targets', [])
        affected = {t['id'] for t in targets if t['repository'] == repository}
        while True:
            expanded = affected | {t['id'] for t in targets if set(t.get('depends_on', [])) & affected}
            if expanded == affected:return affected
            affected = expanded

    def _dependency_binding(self, run, product, repository=None, target_id=None):
        targets = product.get('workflow', {}).get('targets', [])
        selected = [t for t in targets if (repository and t['repository'] == repository) or t['id'] == target_id]
        dependencies = set()
        def visit(target):
            for name in target.get('depends_on', []):
                if name not in dependencies:
                    dependencies.add(name);visit(self.registry.target(product, name))
        for target in selected:visit(target)
        value = {}
        for name in sorted(dependencies):
            target = self.registry.target(product, name)
            candidate = run['candidates'].get(target['repository'])
            value[name] = code_binding(candidate) if candidate else {'outside_scope': True, 'plan': run['plan_sha256']}
        return digest(value)

    def candidate(self, run_id, value):
        scan_sensitive(value)
        if not re.fullmatch('[0-9a-f]{40}', value.get('commit', '')) or not value.get('author'):
            raise WorkbenchError('candidate_invalid', 'Candidate needs a full commit and actual implementer identity')
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            product = self._approved(run)
            repo = self._workspace(product, value)
            if repo['name'] not in {self.registry.target(product, t)['repository'] for t in run['targets']}:
                raise WorkbenchError('scope_mismatch', 'Repository is outside the confirmed plan targets')
            if any(a.get('target_snapshot', {}).get('repository') == repo['name'] for a in self.store.unresolved()):
                raise WorkbenchError('action_unresolved', 'Reconcile this repository previous intents before replacing its candidate')
            value = copy.deepcopy(value)
            value['repository'] = repo['name']
            old = run['candidates'].get(repo['name'])
            if old != value:
                changed_code = not old or code_binding(old) != code_binding(value)
                if changed_code:
                    run['reviews'].pop(repo['name'], None)
                affected = self._dependent_targets(product, repo['name']) if changed_code else {t['id'] for t in product['workflow']['targets'] if t['repository'] == repo['name']}
                for target in product['workflow']['targets']:
                    if target['id'] in affected:
                        if changed_code:
                            run['checks'].pop(target['id'], None)
                            run['reviews'].pop(target['repository'], None)
                        run['acceptances'].pop(target['id'], None)
            run['candidates'][repo['name']] = value
            run['phase'] = 'implementing'
            self.store.put(run)
            self.store.audit(run_id, 'candidate_registered', {'repository': repo['name'], 'commit': value['commit']})
        self.report(run_id)
        return self.status(run_id)

    def review(self, run_id, value):
        scan_sensitive(value)
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            product = self._approved(run)
            repo = self._repository(product, value.get('repository'))
            candidate = run['candidates'].get(repo['name'])
            if not candidate or value.get('commit') != candidate['commit']:
                raise WorkbenchError('review_mismatch', 'Review must reference the current candidate commit')
            reviewer = value.get('reviewer')
            if not reviewer or reviewer == candidate['author']:
                raise WorkbenchError('independent_review_required', 'Reviewer must be identified and independent of implementation')
            status = value.get('status', value.get('verdict'))
            if status not in {'passed', 'failed', 'unverified'}:
                raise WorkbenchError('review_invalid', 'Review status must be passed, failed or unverified')
            if status == 'passed' and any(f.get('severity', f.get('priority')) in {'blocking', 'critical', 'high', 'P0', 'P1', 0, 1} for f in value.get('findings', []) if isinstance(f, dict)):
                raise WorkbenchError('review_blocking_findings', 'Blocking findings cannot be recorded as passed')
            self._workspace(product, candidate)
            reference = self._evidence(run, 'independent_review', value=value, binding={'repository': repo['name'], 'commit': candidate['commit'], 'candidate_sha256': code_binding(candidate)})
            run['reviews'][repo['name']] = {'status': status, 'reviewer': reviewer, 'commit': candidate['commit'], 'candidate_sha256': code_binding(candidate), 'dependency_sha256': self._dependency_binding(run, product, repository=repo['name']), 'evidence': reference}
            self.store.put(run)
            self.store.audit(run_id, 'review_recorded', {'repository': repo['name'], 'status': status, 'reviewer': reviewer})
        self.report(run_id)
        return self.status(run_id)

    def check(self, run_id, target_id, name=None):
        with self.store.lock('iteration:' + run_id):
            run = self.store.get(run_id)
            product = self._approved(run)
            target = self.registry.target(product, target_id)
            if target_id not in run['targets']:
                raise WorkbenchError('scope_mismatch', 'Check target is outside the approved plan')
            candidate = run['candidates'].get(target['repository'])
            if not candidate:
                raise WorkbenchError('candidate_missing', 'Register a committed candidate before running its checks')
            self._workspace(product, candidate)
            checks = [c for c in target.get('checks', []) if name is None or c['id'] == name]
            if not checks:
                raise WorkbenchError('check_unknown', 'No configured check matches')
            results = []
            for check in checks:
                with self.store.lock('check:' + target['repository']):
                    outcome = safe_json(self.adapter.execute_action('check', product, self.root, target, candidate, {'check': check['id']}))
                self._workspace(product, candidate)
                status = 'passed' if outcome.get('status') == 'succeeded' else 'failed' if outcome.get('status') == 'failed' else 'unverified'
                with self.store.transaction():
                    run = self.store.get(run_id)
                    reference = self._evidence(run, 'check:' + check['id'], value=outcome, binding={'commit': candidate['commit'], 'target': target_id, 'candidate_sha256': code_binding(candidate)})
                    record = {'name': check['id'], 'status': status, 'commit': candidate['commit'], 'candidate_sha256': code_binding(candidate), 'configuration_sha256': run['configuration_sha256'], 'dependency_sha256': self._dependency_binding(run, product, target_id=target_id), 'evidence': reference}
                    run['checks'].setdefault(target_id, {})[check['id']] = record
                    self.store.put(run)
                    self.store.audit(run_id, 'check_completed', {'target': target_id, 'name': check['id'], 'status': status})
                results.append(record)
            self.report(run_id)
            return {'iteration': run_id, 'target': target_id, 'status': 'passed' if all(r['status'] == 'passed' for r in results) else 'unverified', 'checks': results}

    def _gate(self, run, product, target, action):
        if target['id'] not in run['targets']:
            raise WorkbenchError('scope_mismatch', 'Release target is outside the confirmed plan')
        if (action in {'archive', 'upload_tf', 'prepare_store'} and target['kind'] != 'ios') or (action in {'deploy', 'smoke', 'rollback'} and target['kind'] not in {'worker', 'web'}):
            raise WorkbenchError('target_action_mismatch', 'Action is not supported for this target kind')
        candidate = run['candidates'].get(target['repository'])
        if not candidate:
            raise WorkbenchError('candidate_missing', 'Target has no committed candidate')
        self._workspace(product, candidate)
        review = run['reviews'].get(target['repository'], {})
        if review.get('status') != 'passed' or review.get('candidate_sha256') != code_binding(candidate) or review.get('dependency_sha256') != self._dependency_binding(run, product, repository=target['repository']):
            raise WorkbenchError('review_required', 'Current candidate needs independent passing review')
        self._verify_evidence(review['evidence'])
        required = target.get('required_checks', [])
        if not required:
            raise WorkbenchError('checks_unconfigured', 'Release needs explicitly configured acceptance checks')
        for check_name in required:
            record = run['checks'].get(target['id'], {}).get(check_name, {})
            if record.get('status') != 'passed' or record.get('candidate_sha256') != code_binding(candidate) or record.get('configuration_sha256') != run['configuration_sha256'] or record.get('dependency_sha256') != self._dependency_binding(run, product, target_id=target['id']):
                raise WorkbenchError('check_required', 'Current candidate has missing or failed required checks')
            self._verify_evidence(record['evidence'])
        if target.get('compatibility_required'):
            compatible = candidate.get('compatibility', {})
            if compatible.get('old_clients_supported') is not True or not compatible.get('evidence'):
                raise WorkbenchError('compatibility_required', 'Backend must demonstrate compatibility with existing clients')
            ref = next((e for e in run['evidence'] if e['id'] == compatible['evidence']), None)
            if not ref or ref.get('binding', {}).get('commit') != candidate['commit']:
                raise WorkbenchError('compatibility_required', 'Compatibility evidence must bind to this commit')
            self._verify_evidence(ref)
        if action not in {'pr', 'archive'}:
            for dependency in target.get('depends_on', []):
                dep = self.registry.target(product, dependency)
                if dependency in run['targets'] and not self._delivered(run, dep):
                    raise WorkbenchError('dependency_pending', 'An in-scope prerequisite target is not yet delivered')
                if dependency not in run['targets']:
                    ref = next((e for e in run['evidence'] if e['source'] == 'dependency:' + dependency and e.get('binding', {}).get('plan_sha256') == run['plan_sha256']), None)
                    if not ref:
                        raise WorkbenchError('dependency_unverified', 'Out-of-scope dependency needs actual compatibility evidence')
                    self._verify_evidence(ref)
        current_actions = [a for a in self.store.actions(run['id']) if a.get('candidate_sha256') == digest(candidate) and a['target'] == target['id'] and a['status'] == 'succeeded' and a.get('configuration_sha256') == run['configuration_sha256'] and a.get('plan_sha256') == run['plan_sha256']]
        for record in current_actions:
            self._action_evidence(record)
        if action == 'merge' and not any(a['kind'] == 'pr' for a in current_actions):
            raise WorkbenchError('pr_required', 'Create a candidate-bound PR before merging')
        if action == 'deploy' and not any(a['kind'] == 'merge' for a in current_actions):
            raise WorkbenchError('merge_required', 'Merge the reviewed candidate before deployment')
        if action in {'smoke', 'rollback'} and not any(a['kind'] == 'deploy' for a in current_actions):
            raise WorkbenchError('deploy_required', 'There is no recorded deployment to validate or roll back')
        if action == 'upload_tf':
            if not candidate.get('artifact'):
                raise WorkbenchError('artifact_required', 'Register the actual IPA digest before upload')
            archives = [a for a in self.store.actions(run['id']) if a['kind'] == 'archive' and a['target'] == target['id'] and a['status'] == 'succeeded' and a.get('candidate', {}).get('commit') == candidate['commit'] and a.get('configuration_sha256') == run['configuration_sha256'] and a.get('plan_sha256') == run['plan_sha256']]
            archive = next((a for a in archives if a.get('outcome', {}).get('evidence', {}).get('artifact', {}).get('sha256') == candidate['artifact']['sha256']), None)
            if not archive:
                raise WorkbenchError('archive_required', 'Upload needs an actual archive/export at this commit with the exact IPA digest')
            self._action_evidence(archive)
        if action == 'deploy' and target.get('rollback_policy') != 'previous_active_version':
            raise WorkbenchError('rollback_unconfigured', 'Deployment requires a configured previous-version rollback policy')
        if action == 'prepare_store':
            if not self._delivered(run, target):
                raise WorkbenchError('delivery_pending', 'Formal preparation requires the verified TestFlight upload')
            acceptance = run['acceptances'].get(target['id'], {})
            if acceptance.get('status') != 'passed' or acceptance.get('candidate_sha256') != digest(candidate):
                raise WorkbenchError('human_acceptance_required', 'Formal preparation requires real human acceptance of this build')
            self._verify_evidence(acceptance['evidence'])
        return candidate

    def _action_evidence(self, record):
        if not record.get('evidence'):
            raise WorkbenchError('evidence_missing', 'Completed external action needs actual recorded evidence')
        self._verify_evidence(record['evidence'])
        if record.get('reconciliation_evidence'):
            self._verify_evidence(record['reconciliation_evidence'])

    def _delivered(self, run, target):
        candidate = run['candidates'].get(target['repository'])
        if not candidate:
            return False
        kinds = {'upload_tf'} if target['kind'] == 'ios' else {'smoke'}
        actions = self.store.actions(run['id'])
        relevant = [a for a in actions if a['target'] == target['id'] and a.get('candidate_sha256') == digest(candidate) and a.get('configuration_sha256') == run['configuration_sha256'] and a.get('plan_sha256') == run['plan_sha256']]
        if any(a['kind'] == 'rollback' and a['status'] in {'running', 'uncertain', 'succeeded'} for a in relevant):
            return False
        delivered = [a for a in relevant if a['kind'] in kinds and a['status'] == 'succeeded']
        for record in delivered:
            self._action_evidence(record)
        return bool(delivered)

    def deliver(self, run_id, target_id, action, parameters=None):
        if action not in ACTIONS:
            raise WorkbenchError('action_forbidden', 'Unknown or forbidden external action; App Store submit/release is never supported')
        parameters = parameters or {}
        scan_sensitive(parameters)
        if {'action', 'original_action', 'original', 'deployment_preflight', 'rollback_version_id', 'authenticated', 'archive_suffix'} & set(parameters):
            raise WorkbenchError('parameters_reserved', 'Recovery and authorization fields are reserved for persisted engine intents')
        with self.store.lock('iteration:' + run_id):
            run = self.store.get(run_id)
            product = self._approved(run)
            target = self.registry.target(product, target_id)
            candidate = self._gate(run, product, target, action)
            resource = target.get('account_id', '') + ':' + target.get('worker_name', target.get('app_id', target['repository']))
            key = digest({'resource': resource, 'kind': action, 'commit': candidate['commit'], 'artifact': candidate.get('artifact', {}).get('sha256'), 'version': candidate.get('version'), 'build': candidate.get('build'), 'rollback_version': parameters.get('version_id') if action == 'rollback' else None})
            with self.store.lock('publisher:' + resource):
                existing = self.store.find_action(key)
                if existing and existing['run'] != run_id:
                    raise WorkbenchError('prior_iteration_action', 'This candidate has an action in another iteration; query and reconcile that iteration before reuse')
                if existing and existing['status'] == 'succeeded':
                    if existing.get('configuration_sha256') != run['configuration_sha256'] or existing.get('plan_sha256') != run['plan_sha256']:
                        raise WorkbenchError('prior_revision_action', 'Historical delivery is bound to a different configuration or plan; use a new candidate or explicitly verify the earlier iteration')
                    self._action_evidence(existing)
                    if action == 'prepare_store':
                        with self.store.transaction():
                            self._finalize(run, product)
                            self.store.put(run)
                            self.store.audit(run_id, 'delivery_recovery_finalized', {'action': existing['id']})
                        self.report(run_id)
                    return {**existing, 'deduplicated': True}
                if existing and existing['status'] in {'running', 'uncertain'}:
                    raise WorkbenchError('action_uncertain', 'Reconcile the previous intent remotely before another dispatch')
                if action == 'deploy':
                    preflight = self.adapter.deployment_preflight(product, self.root, target)
                    if preflight.get('authenticated') is not True:
                        raise WorkbenchError('rollback_unverified', 'Previous active deployment requires authenticated evidence')
                    parameters = {**parameters, 'deployment_preflight': preflight, 'rollback_version_id': preflight['rollback_version_id']}
                    scan_sensitive(parameters)
                if action == 'prepare_store':
                    recorded = run['acceptances'].get(target_id, {}).get('metadata_sha256')
                    if not recorded or recorded != parameters.get('metadata_sha256'):
                        raise WorkbenchError('metadata_acceptance_required', 'The actual human metadata review must bind the exact metadata file digest')
                unresolved = self.store.unresolved()
                if any(a.get('target_snapshot', {}).get('account_id', '') + ':' + a.get('target_snapshot', {}).get('worker_name', a.get('target_snapshot', {}).get('app_id', a.get('target_snapshot', {}).get('repository', ''))) == resource for a in unresolved):
                    raise WorkbenchError('action_uncertain', 'A previous intent on this target still needs reconciliation, even if its candidate changed')
                item = existing or {'id': uuid.uuid4().hex, 'run': run_id, 'target': target_id, 'kind': action, 'dedup': key, 'created_at': now(), 'attempts': 0}
                if action == 'archive':
                    parameters = {**parameters, 'archive_suffix': item['id'] + '-' + str(item['attempts'] + 1)}
                item.update({'status': 'running', 'pid': os.getpid(), 'candidate_sha256': digest(candidate), 'candidate': candidate, 'target_snapshot': target, 'configuration_sha256': run['configuration_sha256'], 'plan_sha256': run['plan_sha256'], 'parameters': parameters, 'attempts': item['attempts'] + 1, 'started_at': now()})
                with self.store.transaction():
                    self.store.put_action(item)
                    self.store.audit(run_id, 'external_intent', {'id': item['id'], 'target': target_id, 'kind': action, 'attempt': item['attempts']})
                try:
                    outcome = safe_json(self.adapter.execute_action(action, product, self.root, target, candidate, parameters))
                    status = outcome.get('status', 'uncertain')
                    if status not in {'succeeded', 'failed', 'uncertain', 'unverified'}:
                        status = 'uncertain'
                except Exception as error:
                    # Once dispatched, exceptions cannot prove that a side effect did not happen.
                    outcome, status = {'reason': type(error).__name__}, 'uncertain'
                with self.store.transaction():
                    run = self.store.get(run_id)
                    reference = self._evidence(run, 'action:' + action, value=outcome, binding={'target': target_id, 'commit': candidate['commit'], 'action': item['id']})
                    item.update({'status': status, 'outcome': outcome, 'evidence': reference, 'finished_at': now()})
                    self.store.put_action(item)
                    run['phase'] = 'delivering' if status == 'succeeded' else 'delivery_attention'
                    if action == 'prepare_store' and status == 'succeeded':
                        self._finalize(run, product)
                    self.store.put(run)
                    self.store.audit(run_id, 'external_result', {'id': item['id'], 'status': status})
                self.report(run_id)
        if action == 'smoke' and item['status'] == 'failed' and target.get('rollback_policy') == 'previous_active_version':
            deployments = [a for a in self.store.actions(run_id) if a['target'] == target_id and a['kind'] == 'deploy' and a['status'] == 'succeeded' and a.get('candidate_sha256') == digest(candidate)]
            if deployments:
                deployment = deployments[-1]
                previous = deployment.get('parameters', {}).get('rollback_version_id') or deployment.get('outcome', {}).get('rollback_version_id')
                if previous:
                    item['automatic_rollback'] = self.deliver(run_id, target_id, 'rollback', {'version_id': previous})
        return item

    def reconcile(self, run_id, action_id):
        with self.store.lock('iteration:' + run_id):
            run = self.store.get(run_id)
            item = self.store.action(action_id)
            if item['run'] != run_id:
                raise WorkbenchError('scope_mismatch', 'Action belongs to another iteration')
            if item['status'] not in {'uncertain', 'running'}:
                if item['kind'] == 'prepare_store' and item['status'] == 'succeeded':
                    self._action_evidence(item)
                    with self.store.transaction():
                        self._finalize(run, self.registry.get(run['product']))
                        self.store.put(run)
                    self.report(run_id)
                return item
            if item['status'] == 'running' and item.get('pid') != os.getpid():
                try:
                    os.kill(item['pid'], 0)
                    raise WorkbenchError('action_active', 'Dispatching process is still active')
                except ProcessLookupError:
                    pass
            product = self.registry.get(run['product'])
            if item['kind'] == 'archive':
                outcome = {'status': 'failed', 'authenticated': True, 'local_only': True, 'reason': 'Interrupted local archive has no verified completion; retry creates fresh archive and export outputs'}
            else:
                outcome = safe_json(self.adapter.execute_action('reconcile', product, self.root, item['target_snapshot'], item['candidate'], {**{k:v for k,v in item.get('parameters', {}).items() if k not in {'action', 'original_action', 'original'}}, 'original_action': item['kind'], 'original': item}))
            if outcome.get('status') not in {'succeeded', 'failed'} or outcome.get('authenticated') is not True:
                raise WorkbenchError('reconciliation_unverified', 'Remote evidence did not establish an authenticated terminal result')
            with self.store.transaction():
                reference = self._evidence(run, 'remote_reconciliation', value=outcome, binding={'action': action_id, 'commit': item['candidate']['commit']})
                if not item.get('evidence'):
                    item['evidence'] = reference
                item.update({'status': outcome['status'], 'reconciliation': outcome, 'reconciliation_evidence': reference, 'reconciled_at': now()})
                self.store.put_action(item)
                if item['status'] == 'succeeded':
                    run['phase'] = 'delivering'
                    if item['kind'] == 'prepare_store':self._finalize(run, product)
                self.store.put(run)
                self.store.audit(run_id, 'external_reconciled', {'id': action_id, 'status': item['status']})
            self.report(run_id)
            return item

    def evidence(self, run_id, file, source, binding=None):
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            reference = self._evidence(run, source, file=file, binding=binding)
            self.store.put(run)
            self.store.audit(run_id, 'evidence_added', {'id': reference['id'], 'source': source})
        return reference

    def accept(self, run_id, value):
        actor, message = value.get('actor', ''), value.get('message', '')
        if not actor or not message or actor.lower() in {'ai', 'agent', 'codex'} or actor.startswith('/root'):
            raise WorkbenchError('human_acceptance_required', 'Use the actual human feedback and identity')
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            product = self.registry.get(run['product'])
            target = self.registry.target(product, value.get('target'))
            if target['id'] not in run['targets']:
                raise WorkbenchError('scope_mismatch', 'Acceptance target is outside this plan')
            candidate = run['candidates'].get(target['repository'])
            if not candidate or value.get('commit') != candidate['commit']:
                raise WorkbenchError('acceptance_mismatch', 'Acceptance must correspond to the current candidate')
            if target['kind'] == 'ios' and (value.get('version') != candidate.get('version') or str(value.get('build')) != str(candidate.get('build'))):
                raise WorkbenchError('acceptance_mismatch', 'Human tested version and build must match the candidate')
            status = value.get('status')
            if status not in {'passed', 'issues', 'pending'}:
                raise WorkbenchError('acceptance_invalid', 'Acceptance is passed, issues or pending')
            if run.get('phase') in {'accepted', 'awaiting_manual_submission'} and status == 'issues':
                self.store.claim(run)
            checks = {ACCEPTANCE_NAMES.get(k, k): v for k, v in value.get('checks', {}).items()}
            if status == 'passed':
                self._approved(run)
                self._gate(run, product, target, 'accept')
                if not self._delivered(run, target):
                    raise WorkbenchError('delivery_pending', 'Human acceptance follows a recorded delivered target')
                for name in target.get('human_acceptances', ['core_path']):
                    if checks.get(name) != 'passed':
                        raise WorkbenchError('human_checks_pending', 'Required human business checks are incomplete')
            reference = self._evidence(run, 'human_acceptance', value=value, binding={'target': target['id'], 'commit': candidate['commit'], 'candidate_sha256': digest(candidate)})
            run['acceptances'][target['id']] = {'status': status, 'actor': actor, 'candidate_sha256': digest(candidate), 'checks': checks, 'metadata_sha256': value.get('metadata_sha256'), 'dependency_sha256': self._dependency_binding(run, product, target_id=target['id']), 'evidence': reference}
            self._finalize(run, product)
            self.store.put(run)
            self.store.audit(run_id, 'human_feedback', {'target': target['id'], 'actor': actor, 'status': status})
        self.report(run_id)
        return self.status(run_id)

    def _finalize(self, run, product):
        if configuration_digest(self.registry.get(run['product'])) != run['configuration_sha256']:
            run['phase'] = 'configuration_attention'
            return
        all_passed = bool(run['targets']) and all(run['acceptances'].get(t, {}).get('status') == 'passed' and run['acceptances'][t].get('candidate_sha256') == digest(run['candidates'].get(self.registry.target(product, t)['repository'])) and run['acceptances'][t].get('dependency_sha256') == self._dependency_binding(run, product, target_id=t) for t in run['targets'])
        if not all_passed:
            run['phase'] = 'feedback_pending'
            return
        ios = [self.registry.target(product, t) for t in run['targets'] if self.registry.target(product, t)['kind'] == 'ios']
        for target in ios:
            candidate = run['candidates'][target['repository']]
            prepared = [a for a in self.store.actions(run['id']) if a['target'] == target['id'] and a['kind'] == 'prepare_store' and a['status'] == 'succeeded' and a.get('candidate_sha256') == digest(candidate) and a.get('plan_sha256') == run['plan_sha256'] and a.get('configuration_sha256') == run['configuration_sha256']]
            if not prepared:
                run['phase'] = 'awaiting_store_preparation'
                return
            for action in prepared:self._action_evidence(action)
        run['phase'] = 'awaiting_manual_submission' if ios else 'accepted'
        self.store.db.execute('DELETE FROM owners WHERE product=? AND run=?', (run['product'], run['id']))

    def control(self, run_id, operation):
        with self.store.lock('iteration:' + run_id), self.store.transaction():
            run = self.store.get(run_id)
            if operation == 'pause':
                run['paused'] = True
            else:
                for action in self.store.actions(run_id):
                    if action['status'] == 'running':
                        try:
                            os.kill(action['pid'], 0)
                        except ProcessLookupError:
                            action['status'] = 'uncertain'
                            self.store.put_action(action)
                run['paused'] = False
            self.store.put(run)
            self.store.audit(run_id, operation, {})
        self.report(run_id)
        return self.status(run_id)

    def status(self, run_id):
        run = self.store.get(run_id)
        return {**run, 'actions': self.store.actions(run_id), 'report_path': str(self._run_path(run_id, 'delivery.md'))}

    def report(self, run_id):
        run = self.status(run_id)
        lines = ['# 迭代交付与验收记录', '', '产品：' + run['product'], '迭代：' + run_id, '计划修订：' + str(run['revision']), '阶段：' + run['phase'], '暂停：' + str(run['paused']), '', '## 候选与检查', '']
        for repo, candidate in run['candidates'].items():
            lines.append('- ' + repo + '：' + candidate['commit'] + '；独立评审 ' + run['reviews'].get(repo, {}).get('status', 'pending'))
        for target in run['targets']:
            checks = run['checks'].get(target, {})
            lines.append('- ' + target + '：检查 ' + (', '.join(k + '=' + v['status'] for k, v in checks.items()) or 'pending') + '；真人验收 ' + run['acceptances'].get(target, {}).get('status', 'pending'))
        lines += ['', '## 外部动作', '']
        for action in run['actions']:
            lines.append('- ' + action['target'] + '/' + action['kind'] + '：' + action['status'] + '；记录 ' + action['id'])
        lines += ['', '记录只表示对应步骤；构建不等于业务验收，上传不等于正式发布。App Store 提审和发布仍由用户操作。', '']
        private_write(self._run_path(run_id, 'delivery.md'), '\n'.join(lines))

    def collect(self, product_name, sources=None, days=28):
        if not 1 <= days <= 365:
            raise WorkbenchError('date_invalid', 'Collection window must be between 1 and 365 days')
        product = self.registry.get(product_name)
        result = safe_json(self.adapter.collect_product(product, self.root, sources or ['ga4', 'apple', 'cloudflare'], days))
        identifier(product['id'])
        relative = 'assessments/' + product['id'] + '/' + uuid.uuid4().hex
        write_json(confined(self.root, relative + '/data.json'), result)
        rows = result.get('sources', [])
        lines = ['# 产品调查数据', '', '产品：' + product['name'], '采集时间：' + now(), '请求窗口：最近 ' + str(days) + ' 天；实际可读区间见数据源记录。', '', '各来源独立判断；缺失收入为未知，低样本不作因果结论，成本未知不报净利润。', '']
        for source in rows:
            lines.append('- ' + str(source.get('source')) + '：' + str(source.get('status')) + '；' + str(source.get('reason', '实际数据见 data.json')))
        private_write(confined(self.root, relative + '/assessment.md'), '\n'.join(lines))
        return {'product': product['id'], 'sources': rows, 'report_path': str(confined(self.root, relative + '/assessment.md')), 'data_path': str(confined(self.root, relative + '/data.json'))}
