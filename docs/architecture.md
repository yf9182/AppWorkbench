# Conversation-led multi-product iterations

Approved design (2026-09-30): assess product -> recommend one version -> human confirms its exact plan revision -> implementation -> independent review and relevant tests -> delivery -> human acceptance. Web/backend PR merge and production deployment may follow passing gates; iOS ends at TestFlight and manual App Store submission/release. No model API or background orchestration.

Code lives in this private repository. Product definitions extend the existing products.json registry under APP_WORKBENCH_HOME; credentials remain referenced by manifest.json IDs. SQLite state and run artifacts are private and external to Git. Evidence records carry hashes, source, observed time and candidate commits. Missing/low-sample data is partial, not zero or a global blocker.

Root owns appworkbench/security.py, errors.py, registry.py, store.py, engine.py, cli.py, migration.py, dashboard.py and tests/test_core.py. Adapter owner owns appworkbench/adapters.py and tests/test_adapters.py. Skill/docs owner owns skills/app-workbench/, README.md, docs/workflow.md, docs/acceptance.md, templates/, scripts/install-skill.sh and CalorieSnapshot docs/AGENTS updates.

## Adapter contract

Public adapter functions (root is a pathlib.Path to the external credential registry):

* inspect_product(product: dict, root: Path) -> list[dict]: checks with capability, status (ready/unverified/blocked), reason, target and checked_at. Read-only inspections; no cloud writes.
* collect_product(product: dict, root: Path, sources: list[str], days: int=28) -> dict: {sources: [{source,status,checked_at,data,reason?}],...}. Source failures are independent; never substitute zero for missing revenue. Source selection ga4/apple/cloudflare/legacy. Private raw output stays in engine evidence artifacts, not Git.
* execute_action(action: str, product: dict, root: Path, target: dict, candidate: dict, parameters: dict) -> dict: {status: succeeded/failed/uncertain/unverified, remote_id?, evidence?, reason?}. Supported gated actions check, pr, merge, deploy, smoke, rollback, archive, upload_tf, prepare_store, reconcile. No submit/release endpoints. Engine writes intent before calling and owns gates/deduplication. Adapter must validate actual target configuration and Git identity and scrub secrets from subprocess outputs. Use explicit argv, never shell=True. No cloud writes during implementation tests/live assessments.

Product workflow extension: {goal, category, timezone, targets:[{id,repository,kind:ios/worker/web/tool,depends_on:[],checks:[{id,argv:[],timeout:seconds}], required_checks:[], deploy_argv:[], smoke_url?, rollback_argv:[], app_id?,bundle_id?,team_id?,worker_name?,account_id?,legacy_ops_home?,legacy_repository?,...}]}. Repository entries gain optional local_path. Candidate: {repository,commit,local_path,author,artifact?:{path,sha256},version?,build?,compatibility?:{old_clients_supported,evidence}}. Execution parameters contain the selected check or actual action parameters, never credential values.

CLI contract: wb init; product list/show/register/inspect; collect PRODUCT; iteration create PRODUCT --plan FILE; iteration approve ID --actor HUMAN --message TEXT; iteration revise/status/pause/resume; candidate set ID --file JSON; review record ID --file JSON; check ID --target TARGET [--name CHECK]; deliver ID --target TARGET --action ACTION; reconcile ID --action-id ID; accept ID --file JSON; evidence add ID --file FILE --source SOURCE; export --output DIR; backup/restore; serve. All commands return {ok,command,result} or {ok:false,error:{code,message}}, process exit nonzero for failed/unknown external actions. Human attestation is recorded from an actual user instruction, not fabricated by a script.

Private run artifacts bind plan SHA256, product configuration SHA256, repository candidates and individual evidence files. Effective target configuration changes invalidate release gates. Required check/review evidence is verified against its stored digest on use. Shared targets have one publisher. TestFlight upload is separate from formal store preparation; human core-path/purchase/restore/rights/metadata evidence is required for the latter.

Acceptance of framework is separate from the two product iteration approvals: assessments and concrete plans are prepared first; actual product implementation, paid tests, uploads and production changes wait for those plan confirmations. The display panel is read-only, local, secret-free and uses exported projections after framework validation.
