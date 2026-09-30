import datetime
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from appworkbench import adapters as a
from appworkbench.errors import WorkbenchError


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        for args in (["git", "init", "-q"], ["git", "config", "user.name", "Fixture"],
                     ["git", "config", "user.email", "fixture@example.invalid"],
                     ["git", "remote", "add", "origin", "https://github.com/fixture/app.git"]):
            subprocess.run(args, cwd=self.checkout, check=True, capture_output=True)
        (self.checkout / "wrangler.jsonc").write_text('// old "name": "wrong"\n{"name":"app", "account_id":"' + 'a' * 32 + '", "env":{"staging":{"name":"other"}},}')
        subprocess.run(["git", "add", "."], cwd=self.checkout, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=self.checkout, check=True, capture_output=True)
        self.commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.checkout).decode().strip()
        self.target = {"id": "app", "repository": "app", "kind": "worker", "account_id": "a" * 32,
                       "worker_name": "app", "wrangler_config": "wrangler.jsonc",
                       "deploy_argv": ["npx", "--no-install", "wrangler", "deploy"],
                       "checks": [{"id": "actual", "argv": ["python3", "-c", "raise SystemExit(0)"]}]}
        self.product = {"id": "fixture", "targets": [self.target], "repositories": [
            {"name": "app", "owner": "fixture", "local_path": str(self.checkout)}]}
        self.candidate = {"repository": "app", "commit": self.commit, "local_path": str(self.checkout)}

    def test_archive_uses_new_paths_and_exports_the_new_archive(self):
        import plistlib
        (self.checkout/'App.xcodeproj').mkdir();stale=self.root/'base.xcarchive';stale.mkdir();(stale/'Info.plist').write_bytes(b'stale')
        target=dict(self.target,kind='ios',project='App.xcodeproj',scheme='App',bundle_id='com.fixture.App',team_id='TEAM',archive_path=str(stale),ipa_path=str(self.root/'ipa/App.ipa'),archive_argv=['xcodebuild','-project','App.xcodeproj','-scheme','App','-archivePath',str(stale),'archive'],export_argv=['xcodebuild','-exportArchive','-archivePath',str(stale),'-exportPath',str(self.root/'ipa')])
        candidate=dict(self.candidate,version='1.0',build='1');seen=[]
        def execute(argv,*args,**kwargs):
            seen.append(argv.copy())
            if 'archive' in argv:
                archive=Path(argv[argv.index('-archivePath')+1]);archive.mkdir();(archive/'Info.plist').write_bytes(plistlib.dumps({'ApplicationProperties':{'CFBundleIdentifier':'com.fixture.App','CFBundleShortVersionString':'1.0','CFBundleVersion':'1'}}))
            else:
                output=Path(argv[argv.index('-exportPath')+1]);output.mkdir();(output/'App.ipa').write_bytes(b'newly-exported-candidate')
            return {'status':'succeeded'}
        with patch.object(a,'_repository',return_value=(self.checkout,'fixture/app')),patch.object(a,'_run',side_effect=execute),patch.object(a,'_inspect_ipa',return_value={'bundle_id':'com.fixture.App','team_id':'TEAM','version':'1.0','build':'1'}):
            result=a.execute_action('archive',self.product,self.root,target,candidate,{'archive_suffix':'intent-1'})
        self.assertEqual(result['status'],'succeeded');self.assertEqual(seen[0][seen[0].index('-archivePath')+1],seen[1][seen[1].index('-archivePath')+1]);self.assertNotEqual(seen[0][seen[0].index('-archivePath')+1],str(stale));self.assertEqual((stale/'Info.plist').read_bytes(),b'stale');self.assertTrue(Path(result['evidence']['artifact']['path']).is_file())
    def test_archive_wrong_output_refused_before_execution(self):
        (self.checkout/'App.xcodeproj').mkdir()
        target=dict(self.target,kind='ios',project='App.xcodeproj',scheme='App',archive_path=str(self.root/'B.xcarchive'),archive_argv=['xcodebuild','-project','App.xcodeproj','-scheme','App','-archivePath',str(self.root/'A.xcarchive'),'archive'])
        with patch.object(a,'_repository',return_value=(self.checkout,'fixture/app')), patch.object(a,'_run') as run:
            with self.assertRaises(WorkbenchError):a.execute_action('archive',self.product,self.root,target,self.candidate,{'archive_suffix':'intent-1'})
            run.assert_not_called()
    def test_archive_project_outside_candidate_refused(self):
        target=dict(self.target,kind='ios',project='/unrelated/App.xcodeproj',scheme='App',archive_path=str(self.root/'B.xcarchive'),archive_argv=['xcodebuild','-project','/unrelated/App.xcodeproj','-scheme','App','-archivePath',str(self.root/'B.xcarchive'),'archive'])
        with patch.object(a,'_repository',return_value=(self.checkout,'fixture/app')), patch.object(a,'_run') as run:
            with self.assertRaises(WorkbenchError):a.execute_action('archive',self.product,self.root,target,self.candidate,{'archive_suffix':'intent-1'})
            run.assert_not_called()
    def test_smoke_unknown_intent_reconciles_only_candidate_active(self):
        def remote(*args):
            if args[0].endswith('/versions'):return {'result':{'items':[{'id':'version','annotations':{'workers/message':'AppWorkbench candidate '+self.commit}}]}}
            return {'result':{'deployments':[{'id':'deployment','versions':[{'version_id':'version','percentage':100}]}]}}
        with patch.object(a,'_cf_auth',return_value=('fake','https://fixture.invalid')), patch.object(a,'_json_api',side_effect=remote), patch.object(a,'execute_action',return_value={'status':'succeeded','evidence':{'http_status':200}}):
            result=a._reconcile(self.product,self.root,self.target,self.candidate,{'original_action':'smoke'});self.assertTrue(result['authenticated']);self.assertEqual(result['status'],'succeeded')
    def test_original_action_takes_precedence_over_parameter_override(self):
        with patch.object(a,'_worker_versions',return_value=[]),patch.object(a,'_cf_auth') as auth:
            result=a._reconcile(self.product,self.root,self.target,self.candidate,{'original_action':'deploy','action':'rollback','version_id':'old'})
        self.assertEqual(result['status'],'unverified');auth.assert_not_called()
    def test_actual_git_and_check(self):
        result = a.execute_action("check", self.product, self.root, self.target, self.candidate, {"check": "actual"})
        self.assertEqual(result["status"], "succeeded")
        self.assertNotIn("_stdout", result)

    def test_changed_candidate_refused_before_check(self):
        (self.checkout / "untracked").write_text("changed")
        with self.assertRaises(WorkbenchError):
            a.execute_action("check", self.product, self.root, self.target, self.candidate, {"check": "actual"})

    def test_origin_mismatch(self):
        subprocess.run(["git", "remote", "set-url", "origin", "https://github.com/another/app.git"], cwd=self.checkout, check=True)
        with self.assertRaises(WorkbenchError):
            a._repository(self.product, self.target, self.candidate)

    def test_wranger_top_level_and_comments(self):
        self.assertEqual(a._wrangler_identity(self.checkout, self.target), str((self.checkout / "wrangler.jsonc").resolve()))
        target = dict(self.target, worker_name="other")
        with self.assertRaises(WorkbenchError):
            a._wrangler_identity(self.checkout, target)

    def test_target_override_refused_before_cloud_write(self):
        target = dict(self.target, deploy_argv=["wrangler", "deploy", "--name=other"])
        with patch.object(a, "_cf_auth", return_value=("fake", "https://fixture.invalid")), patch.object(a, "_json_api") as api:
            with self.assertRaises(WorkbenchError):
                a.execute_action("deploy", self.product, self.root, target, self.candidate, {})
            api.assert_not_called()

    def test_cloudflare_account_mismatch(self):
        with patch.object(a, "_credential", return_value=({"account_id": "b" * 32}, self.root / "missing")):
            with self.assertRaises(WorkbenchError):
                a._cf_auth(self.product, self.root, self.target)

    def test_partial_collection_does_not_zero_revenue(self):
        with patch.object(a, "_ga4", side_effect=WorkbenchError("http", "Unavailable")), \
             patch.object(a, "_apple", return_value={"status": "ready", "apps": []}):
            value = a.collect_product(self.product, self.root, ["ga4", "apple"], 7)
        self.assertEqual(value["status"], "partial")
        self.assertEqual(value["sources"][1]["status"], "ready")
        self.assertNotIn("revenue", json.dumps(value["sources"][0]))

    def test_sales_currency_and_unknown_rows(self):
        raw = b"SKU\tApple Identifier\tParent Identifier\tUnits\tDeveloper Proceeds\tCurrency of Proceeds\napp\t1\t\t2\t1.20\tUSD\nsub\t2\tapp\t-1\t2.00\tEUR\nother\t99\t\t2\t100\tUSD\n"
        result = a._sales(raw, "1", "app")
        self.assertEqual(result["proceeds_by_currency"], {"USD": "2.40", "EUR": "-2.00"})
        missing = a._sales(raw, "42", "unknown")
        self.assertFalse(missing["revenue_known"])
        self.assertEqual(missing["proceeds_by_currency"], {})

    def test_platform_identity_mismatch(self):
        with patch.object(a, "_json_api", return_value={"data": {"id": "1", "attributes": {"bundleId": "wrong"}}}):
            with self.assertRaises(WorkbenchError):
                a._apple_identity("fake", "1", "expected")

    def test_process_output_not_leaked(self):
        result = a._safe_result(a._run(["python3", "-c", "print('opaque-secret-without-recognizable-prefix')"]))
        self.assertNotIn("opaque-secret", json.dumps(result))
        self.assertIn("stdout_sha256", result)

    def test_mutation_timeout_uncertain(self):
        with patch.object(a.subprocess, "run", side_effect=subprocess.TimeoutExpired(["fixture"], 1)):
            self.assertEqual(a._run(["fixture"], external=True)["status"], "uncertain")
            self.assertEqual(a._run(["fixture"])["status"], "failed")

    def test_upload_missing_artifact_never_dispatches(self):
        with patch.object(a, "_run") as run:
            result = a._upload_ipa(self.product, self.root, {"app_id": "1"}, self.candidate, "fake")
        self.assertEqual(result["status"], "unverified")
        run.assert_not_called()

    def test_ipa_development_profile_refused(self):
        import zipfile
        import plistlib
        ipa = self.root / "bad.ipa"
        with zipfile.ZipFile(ipa, "w") as archive:
            archive.writestr("Payload/Test.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "fixture.app"}))
            archive.writestr("Payload/Test.app/embedded.mobileprovision", "fake")
        profile = {"Entitlements": {"get-task-allow": True}, "ExpirationDate": datetime.datetime.now() + datetime.timedelta(days=1)}
        with patch.object(a, "_run", return_value={"status": "succeeded", "_stdout": plistlib.dumps(profile)}):
            with self.assertRaises(WorkbenchError):
                a._inspect_ipa(ipa)

    def test_remote_worker_version_without_active_deployment_not_success(self):
        candidate = dict(self.candidate)
        version = {"id": "version", "annotations": {"workers/message": "AppWorkbench candidate " + candidate["commit"]}}
        with patch.object(a, "_worker_versions", return_value=[version]), \
             patch.object(a, "_cf_auth", return_value=("fake", "https://fixture.invalid")), \
             patch.object(a, "_json_api", return_value={"result": {"deployments": [{"versions": [{"version_id": "other", "percentage": 100}]}]}}):
            result = a._reconcile(self.product, self.root, self.target, candidate, {"action": "deploy"})
        self.assertEqual(result["status"], "unverified")
        self.assertTrue(result["evidence"]["authenticated_remote"])
        self.assertTrue(result["authenticated"])

    def test_no_submit_or_release(self):
        for action in ("submit", "release", "invite_testers"):
            with self.assertRaises(WorkbenchError):
                a.execute_action(action, self.product, self.root, self.target, self.candidate, {})

    def test_rollback_verified_remote_active_version(self):
        version = "a" * 8 + "-" + "b" * 4 + "-" + "c" * 4 + "-" + "d" * 4 + "-" + "e" * 12
        remote = {"result": {"deployments": [{"id": "deployment", "versions": [{"version_id": version, "percentage": 100}]}]}}
        with patch.object(a, "_cf_auth", return_value=("fake", "https://fixture.invalid")), patch.object(a, "_json_api", return_value=remote):
            result = a._reconcile(self.product, self.root, self.target, self.candidate, {"action": "rollback", "version_id": version})
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["evidence"]["authenticated_remote"])
        self.assertTrue(result["authenticated"])

    def test_inspection_supports_registry_workflow(self):
        product = dict(self.product, targets=[])
        product["workflow"] = {"targets": [self.target]}
        checks = a.inspect_product(product, self.root)
        self.assertEqual(checks[0]["status"], "ready")
        self.assertEqual(checks[0]["target"], "app")

    def store_fixture(self):
        image = self.root / "screen.png"
        image.write_bytes(b"reviewed screenshot bytes")
        self.metadata = self.root / "metadata.json"
        self.metadata.write_text(json.dumps({"localizations": [{"locale": "en-US", "description": "Reviewed description",
            "screenshots": [{"display_type": "APP_IPHONE_67", "file": str(image), "sha256": a.sha256_file(image)}]}]}))
        self.parameters = {"metadata_file": str(self.metadata), "metadata_sha256": a.sha256_file(self.metadata)}
        self.spec, self.metadata_digest = a._store_spec(self.parameters)
        self.store_target = {"app_id": "1", "bundle_id": "fixture.app"}
        self.store_candidate = dict(self.candidate, version="1.2", build="3")
        self.store_build = {"id": "build", "attributes": {"processingState": "VALID", "expired": False}}

    def store_api(self, url, *args, **kwargs):
        if "/apps/1/appStoreVersions?" in url:
            return {"data": [{"id": "draft", "attributes": {"appStoreState": "PREPARE_FOR_SUBMISSION"}}]}
        if "?include=build" in url:
            return {"data": {"id": "draft", "attributes": {"platform": "IOS", "versionString": "1.2", "releaseType": "MANUAL", "appStoreState": "PREPARE_FOR_SUBMISSION"},
                             "relationships": {"build": {"data": {"id": "build"}}}}}
        if url.endswith("/appStoreVersionLocalizations"):
            return {"data": [{"id": "locale", "attributes": {"locale": "en-US", "description": "Reviewed description"}}]}
        if url.endswith("/appScreenshotSets"):
            return {"data": [{"id": "screens", "attributes": {"screenshotDisplayType": "APP_IPHONE_67"}}]}
        if url.endswith("/appScreenshots"):
            image = self.spec[0]["screenshots"][0]
            return {"data": [{"id": "image", "attributes": {"sourceFileChecksum": image["checksum"], "fileSize": image["file_size"], "assetDeliveryState": {"state": "COMPLETE"}}}]}
        return {"data": {"id": "draft"}}

    def test_store_verified_locales_and_screenshot_bytes(self):
        self.store_fixture()
        with patch.object(a, "_builds", return_value=[self.store_build]), patch.object(a, "_json_api", side_effect=self.store_api):
            result = a._store_verify("fake", self.store_target, self.store_candidate, self.spec, self.metadata_digest)
        self.assertEqual(result["status"], "succeeded")
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["evidence"]["state"], "awaiting_manual_submission")

    def test_store_screenshot_false_boolean_cannot_replace_byte_proof(self):
        self.store_fixture()
        original = self.store_api
        def transport(url, *args, **kwargs):
            value = original(url, *args, **kwargs)
            if url.endswith("/appScreenshots"):
                value["data"][0]["attributes"]["sourceFileChecksum"] = "wrong"
            return value
        with patch.object(a, "_builds", return_value=[self.store_build]), patch.object(a, "_json_api", side_effect=transport):
            result = a._store_verify("fake", self.store_target, self.store_candidate, self.spec, self.metadata_digest)
        self.assertEqual(result["status"], "unverified")
        self.assertTrue(result["authenticated"])

    def test_store_mutated_incomplete_readback_is_uncertain(self):
        self.store_fixture()
        with patch.object(a, "_builds", return_value=[self.store_build]), \
             patch.object(a, "_json_api", side_effect=self.store_api) as transport, \
             patch.object(a, "_request", return_value=(204, b"")), \
             patch.object(a, "_store_verify", return_value={"status": "unverified", "authenticated": True, "reason": "Screenshots missing"}):
            result = a._prepare_store(self.product, self.root, self.store_target, self.store_candidate, "fake", self.parameters)
        self.assertEqual(result["status"], "uncertain")
        self.assertTrue(any(len(call.args) > 2 for call in transport.call_args_list))

    def test_store_metadata_digest_mismatch_before_mutation(self):
        self.store_fixture()
        (self.root / "metadata.json").write_text("changed after review")
        with patch.object(a, "_json_api") as transport:
            result = a._prepare_store(self.product, self.root, self.store_target, self.store_candidate, "fake", self.parameters)
        self.assertEqual(result["status"], "unverified")
        transport.assert_not_called()

    def test_deploy_preflight_rejects_ambiguous_active_versions(self):
        target = dict(self.target, rollback_policy="previous_active_version")
        with patch.object(a, "_active_deployment", return_value={"id": "active", "versions": [{"version_id": "a", "percentage": 50}, {"version_id": "b", "percentage": 50}]}):
            with self.assertRaises(WorkbenchError):
                a.deployment_preflight(self.product, self.root, target)

    def test_deploy_preflight_returns_only_remote_rollback_identity(self):
        target = dict(self.target, rollback_policy="previous_active_version")
        active = {"id": "active", "versions": [{"version_id": "prior", "percentage": 100}], "annotations": {"note": "opaque-private-comment"}}
        with patch.object(a, "_active_deployment", return_value=active):
            result = a.deployment_preflight(self.product, self.root, target)
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["rollback_version_id"], "prior")
        self.assertNotIn("opaque-private", json.dumps(result))

    def test_failed_gh_query_cannot_claim_authenticated_reconciliation(self):
        with patch.object(a, "_repository", return_value=(self.checkout, "fixture/app")), \
             patch.object(a, "_run", return_value={"status": "failed", "_stdout": b"{}"}):
            result = a._reconcile(self.product, self.root, self.target, self.candidate, {"action": "merge", "pr_number": "1"})
        self.assertEqual(result["status"], "unverified")
        self.assertNotIn("authenticated", result)

    def test_changed_active_deployment_refuses_before_write(self):
        target = dict(self.target, rollback_policy="previous_active_version")
        current = {"authenticated": True, "rollback_version_id": "new", "previous_deployment": {"id": "new-deployment"}}
        recorded = {"authenticated": True, "rollback_version_id": "old", "previous_deployment": {"id": "old-deployment"}}
        with patch.object(a, "_repository", return_value=(self.checkout.resolve(), "fixture/app")), \
             patch.object(a, "_cf_auth", return_value=("fake", "https://fixture.invalid")), \
             patch.object(a, "deployment_preflight", return_value=current), patch.object(a, "_run") as dispatch:
            result = a.execute_action("deploy", self.product, self.root, target, self.candidate, {"deployment_preflight": recorded})
        self.assertEqual(result["status"], "unverified")
        dispatch.assert_not_called()

    def test_inspection_missing_executable_is_blocked(self):
        with patch.object(a.shutil, "which", return_value=None):
            checks = a.inspect_product(self.product, self.root)
        self.assertEqual(next(row for row in checks if row["capability"] == "check")["status"], "blocked")
        self.assertEqual(next(row for row in checks if row["capability"] == "deploy")["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
