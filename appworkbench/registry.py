"""Extend, never replace, the shared product/credential registry."""
import copy
import json
import os
from pathlib import Path
import re

from .errors import WorkbenchError
from .security import confined, digest, private_dir, read_json, scan_sensitive, write_json

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')

def identifier(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise WorkbenchError('invalid_identifier', 'Expected a bounded product, target or repository identifier')
    return value

def configuration_digest(product):
    value = copy.deepcopy(product)
    for repository in value.get('repositories', []):
        repository.pop('local_path', None)
    for target in value.get('workflow', {}).get('targets', []):
        for name in ('legacy_ops_home', 'legacy_repository', 'export_options', 'archive_path', 'ipa_path'):
            target.pop(name, None)
    return digest(value)

class Registry:
    def __init__(self, root):
        self.root = Path(root).expanduser().resolve()

    def document(self):
        path = confined(self.root, 'products.json')
        if not path.exists():
            return {'schema_version': 1, 'products': []}
        value = read_json(path)
        if not isinstance(value, dict) or not isinstance(value.get('products'), list):
            raise WorkbenchError('registry_invalid', 'Product registry has an invalid structure')
        return value

    def all(self):
        return self.document()['products']

    def get(self, name):
        hits = [p for p in self.all() if name.lower() in {p['id'].lower(), p['name'].lower()}]
        if name == 'calorie-snapshot':
            hits = [p for p in self.all() if p['id'] == 'caloriesnapshot']
        if len(hits) != 1:
            raise WorkbenchError('product_unknown', 'Product must resolve to one registered identity')
        return hits[0]

    def validate(self, product):
        scan_sensitive(product)
        identifier(product.get('id'))
        if not product.get('name') or not isinstance(product.get('repositories'), list):
            raise WorkbenchError('product_invalid', 'Product needs a name and repositories')
        manifest = read_json(self.root / 'manifest.json') if (self.root / 'manifest.json').exists() else {'credentials': {}}
        known = manifest.get('credentials', {})
        if isinstance(known, list):
            known = {x['id']: x for x in known}
        for ref in product.get('credential_refs', {}).values():
            if ref not in known:
                raise WorkbenchError('credential_unknown', 'Product references an unknown credential')
        repositories = {}
        for repo in product['repositories']:
            name = identifier(repo.get('name'))
            identifier(repo.get('owner'))
            if name in repositories:
                raise WorkbenchError('product_invalid', 'Duplicate repository identity')
            repositories[name] = repo
        targets = product.get('workflow', {}).get('targets', [])
        ids = [identifier(t.get('id')) for t in targets]
        if len(set(ids)) != len(ids):
            raise WorkbenchError('target_invalid', 'Duplicate target identity')
        for target in targets:
            if target.get('repository') not in repositories or target.get('kind') not in {'ios', 'worker', 'web', 'tool'}:
                raise WorkbenchError('target_invalid', 'Target needs a registered repository and supported kind')
            checks = target.get('checks', [])
            check_ids = [identifier(c.get('id')) for c in checks]
            if len(set(check_ids)) != len(check_ids) or not set(target.get('required_checks', check_ids)).issubset(check_ids):
                raise WorkbenchError('check_invalid', 'Required checks must reference unique configured checks')
            for check in checks:
                if not isinstance(check.get('argv'), list) or not check['argv'] or not all(isinstance(x, str) for x in check['argv']):
                    raise WorkbenchError('check_invalid', 'Checks need explicit argument arrays')
            for dependency in target.get('depends_on', []):
                if dependency not in ids or dependency == target['id']:
                    raise WorkbenchError('dependency_invalid', 'Target dependency is invalid')
            if target.get('kind') == 'ios':
                apps = product.get('app_store_apps', [])
                if not apps or not any(str(a['app_store_id']) == str(target.get('app_id')) and a['bundle_id'] == target.get('bundle_id') for a in apps):
                    raise WorkbenchError('identity_mismatch', 'iOS target must match its registered App Store identity')
            if target.get('worker_name'):
                workers = product.get('cloudflare_workers', [])
                if not any(w['worker_name'] == target['worker_name'] and w['repository'] == target['repository'] and w['account_id'] == target.get('account_id') for w in workers):
                    raise WorkbenchError('identity_mismatch', 'Worker target must match its registered cloud resource')
        edges = {t['id']: t.get('depends_on', []) for t in targets}
        def visit(node, stack):
            if node in stack:
                raise WorkbenchError('dependency_cycle', 'Release targets contain a cycle')
            for child in edges[node]:
                visit(child, stack | {node})
        for node in ids:
            visit(node, set())
        return product

    def register(self, product):
        self.validate(product)
        value = self.document()
        value['products'] = [p for p in value['products'] if p['id'] != product['id']] + [product]
        write_json(self.root / 'products.json', value)
        return product

    def initialize(self, source_root=None):
        private_dir(self.root)
        value = self.document()
        source_root = Path(source_root or Path.home() / 'AppWorkbenchSources')
        tools = {'segdemo', 'xmind-to-testcases', 'xmind-to-testcase-excel', 'prd-to-testcase', 'fpd', 'mantis', 'trendradar', 'rdd'}
        libraries = {'samkit', 'imagesresource', 'videoeditor'}
        services = {'material-hub', 'benefitcenter', 'ai-pixpaint-backend', 'easycal-backend'}
        for product in value['products']:
            for repo in product['repositories']:
                local = Path.home() / repo['name'] if repo['name'] == 'CalorieSnapshot' else source_root / repo['name']
                if local.is_dir() and not repo.get('local_path'):
                    repo['local_path'] = str(local.resolve())
            if product.get('workflow'):
                continue
            category = 'tool' if product['id'] in tools else 'library' if product['id'] in libraries else 'shared_service' if product['id'] in services else 'product'
            targets = []
            for worker in product.get('cloudflare_workers', []):
                name = worker['repository']
                targets.append({'id': name.lower() if sum(w['repository'] == name for w in product.get('cloudflare_workers', [])) == 1 else worker['worker_name'], 'repository': name, 'kind': 'worker', 'worker_name': worker['worker_name'], 'account_id': worker['account_id'], 'wrangler_config': worker.get('source_configuration', 'wrangler.jsonc'), 'checks': [], 'required_checks': [], 'depends_on': [], 'deploy_argv': ['pnpm', 'exec', 'wrangler', 'deploy'], 'rollback_policy': 'previous_active_version', 'smoke_url': 'https://' + worker['worker_name'] + '.yangf999212.workers.dev/'})
            for app in product.get('app_store_apps', []):
                ios = next((x['repository'] for x in product.get('firebase_ios', []) if x['bundle_id'] == app['bundle_id']), product['repositories'][0]['name'])
                targets.append({'id': ios.lower(), 'repository': ios, 'kind': 'ios', 'app_id': str(app['app_store_id']), 'bundle_id': app['bundle_id'], 'team_id': 'Z3YH9HL8H3', 'checks': [], 'required_checks': [], 'depends_on': []})
            covered = {t['repository'] for t in targets}
            for repo in product['repositories']:
                if repo['name'] not in covered:
                    targets.append({'id': repo['name'].lower(), 'repository': repo['name'], 'kind': 'tool', 'checks': [], 'required_checks': [], 'depends_on': []})
            product['workflow'] = {'category': category, 'goal': None, 'timezone': 'Asia/Shanghai', 'model_policy': 'inherit_conversation', 'schedule_enabled': False, 'paid_test_budget': 0, 'targets': targets, 'shared_services': []}
            if product['id'] == 'caloriesnapshot':
                for target in targets:
                    target.update({'legacy_ops_home': str(Path.home() / '.config/calorie-ops'), 'legacy_repository': str(Path.home() / 'CalorieSnapshot'), 'project': 'CalorieSnapshot.xcodeproj', 'scheme': 'CalorieSnapshot', 'checks': [{'id': 'build', 'argv': ['xcodebuild', '-project', 'CalorieSnapshot.xcodeproj', '-scheme', 'CalorieSnapshot', '-destination', 'generic/platform=iOS Simulator', 'CODE_SIGNING_ALLOWED=NO', 'build'], 'timeout': 900}], 'required_checks': ['build'], 'human_acceptances': ['device_install', 'core_path', 'purchase', 'restore', 'existing_entitlements', 'metadata_review']})
            if product['id'] == 'ai-pet-studio':
                backend = 'aipetstudio-backend'
                for target in targets:
                    name = target['repository']
                    if name == 'AIPetStudio-Backend':
                        target.update({'checks': [{'id': 'typecheck', 'argv': ['pnpm', 'exec', 'tsc', '--noEmit'], 'timeout': 180}, {'id': 'webhook', 'argv': ['node', 'scripts/test-revenuecat-webhook.mjs'], 'timeout': 180}, {'id': 'pet-translator', 'argv': ['node', 'scripts/test-pet-translator.mjs'], 'timeout': 180}], 'required_checks': ['typecheck', 'webhook', 'pet-translator'], 'smoke_url': 'https://ai-pet-studio-backend.yangf999212.workers.dev/healthz', 'compatibility_required': True})
                    elif name == 'AIPetStudio-Web':
                        target.update({'kind': 'web', 'checks': [{'id': 'typecheck', 'argv': ['pnpm', 'run', 'typecheck'], 'timeout': 180}, {'id': 'lint', 'argv': ['pnpm', 'run', 'lint'], 'timeout': 180}, {'id': 'build', 'argv': ['pnpm', 'exec', 'opennextjs-cloudflare', 'build'], 'timeout': 600}], 'required_checks': ['typecheck', 'lint', 'build'], 'depends_on': [backend]})
                    else:
                        target.update({'project': 'AIPetStudio.xcodeproj', 'scheme': 'AIPetStudio', 'checks': [{'id': 'build', 'argv': ['xcodebuild', '-project', 'AIPetStudio.xcodeproj', '-scheme', 'AIPetStudio', '-destination', 'generic/platform=iOS Simulator', 'CODE_SIGNING_ALLOWED=NO', 'build'], 'timeout': 900}], 'required_checks': ['build'], 'depends_on': [backend], 'human_acceptances': ['device_install', 'core_path', 'purchase', 'restore', 'existing_entitlements', 'metadata_review']})
                product['workflow']['shared_services'] = ['material-hub']
            self.validate(product)
        write_json(self.root / 'products.json', value)
        return {'products': len(value['products']), 'repositories': sum(len(p['repositories']) for p in value['products']), 'runtime_root': str(self.root), 'model_policy': 'inherit_conversation', 'schedules_created': False}

    def target(self, product, target_id):
        hits = [t for t in product.get('workflow', {}).get('targets', []) if t['id'] == target_id]
        if len(hits) != 1:
            raise WorkbenchError('target_unknown', 'Target must resolve to one registered release identity')
        return hits[0]
