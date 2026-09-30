"""Platform transports. The engine owns authorization, locks and durable intents.

No transport response or child output is printed. Error messages deliberately do
not interpolate exceptions, request bodies, authentication or command output.
"""
from __future__ import annotations

import base64
import csv
import datetime as dt
import decimal
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import tempfile
import zipfile
import plistlib
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
import urllib.error
import urllib.parse
import urllib.request

from .errors import WorkbenchError
from .security import credential_path, now, safe_json, scan_sensitive, sha256_file


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def _request(url, token=None, body=None, method=None, content_type="application/json", accept="application/json"):
    if not url.startswith("https://"):
        raise WorkbenchError("transport", "Platform API requires HTTPS")
    headers = {"Accept": accept}
    if token:
        headers["Authorization"] = "Bearer " + token
    if body is not None:
        headers["Content-Type"] = content_type
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
    request = urllib.request.Request(url, headers=headers, data=body, method=method)
    try:
        with urllib.request.build_opener(_NoRedirect).open(request, timeout=45) as response:
            raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise WorkbenchError("transport", "Platform response exceeds size limit")
            return response.status, raw
    except urllib.error.HTTPError as error:
        return error.code, b""
    except (urllib.error.URLError, TimeoutError, OSError):
        raise WorkbenchError("transport", "Platform connection failed") from None


def _json_api(url, token=None, body=None, method=None):
    code, raw = _request(url, token, body, method)
    if code < 200 or code >= 300:
        raise WorkbenchError("http", "Platform API returned HTTP %s" % code)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise WorkbenchError("transport", "Invalid platform response") from None
    if isinstance(value, dict) and value.get("success") is False:
        raise WorkbenchError("http", "Platform API rejected the operation")
    return value


def _manifest(root):
    return json.loads((root / "manifest.json").read_text())["credentials"]


def _credential(product, root, provider, default):
    identifier = product.get("credential_refs", {}).get(provider, default)
    item = _manifest(root).get(identifier)
    if not item:
        raise WorkbenchError("credential", "Platform credential reference is unavailable")
    return item, credential_path(root, identifier)


def _jwt(claims, key, algorithm, kid=None):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, utils
    b64 = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    header = {"alg": algorithm, "typ": "JWT"}
    if kid:
        header["kid"] = kid
    unsigned = (b64(json.dumps(header).encode()) + "." + b64(json.dumps(claims).encode())).encode()
    private = serialization.load_pem_private_key(key, password=None)
    if algorithm == "RS256":
        signature = private.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
    else:
        r, s = utils.decode_dss_signature(private.sign(unsigned, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return unsigned.decode() + "." + b64(signature)


def _apple_token(product, root):
    item, path = _credential(product, root, "apple_api", "apple-app-store-connect")
    stamp = int(time.time())
    return _jwt({"iss": item["issuer_id"], "iat": stamp, "exp": stamp + 600,
                 "aud": "appstoreconnect-v1"}, path.read_bytes(), "ES256", item["key_id"]), item


def _google_token(product, root):
    _, path = _credential(product, root, "google_analytics", "google-ga4-reader")
    source = json.loads(path.read_text())
    stamp = int(time.time())
    assertion = _jwt({"iss": source["client_email"], "iat": stamp, "exp": stamp + 3600,
                      "aud": "https://oauth2.googleapis.com/token",
                      "scope": "https://www.googleapis.com/auth/analytics.readonly"},
                     source["private_key"].encode(), "RS256")
    payload = urllib.parse.urlencode({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                     "assertion": assertion}).encode()
    code, raw = _request("https://oauth2.googleapis.com/token", body=payload,
                         content_type="application/x-www-form-urlencoded")
    if code != 200:
        raise WorkbenchError("oauth", "Google authorization failed")
    try:
        return json.loads(raw)["access_token"]
    except (ValueError, KeyError):
        raise WorkbenchError("oauth", "Google authorization response is invalid") from None


def _identifier(value, pattern=r"[A-Za-z0-9_.-]+"):
    value = str(value)
    if not re.fullmatch(pattern, value):
        raise WorkbenchError("identity", "Invalid platform target identifier")
    return value


def _ga4(product, root, days):
    identities = {}
    for row in product.get("firebase_ios", []):
        if row.get("ga4_property_id"):
            identities.setdefault(str(row["ga4_property_id"]), []).append({"role": "primary",
                "repository": row.get("repository"), "firebase_project_id": row.get("project_id"), "bundle_id": row.get("bundle_id")})
    for row in product.get("additional_ga4_properties", []):
        if row.get("property_id"):
            identities.setdefault(str(row["property_id"]), []).append({"role": "secondary",
                "firebase_project_id": row.get("firebase_project_id")})
    ids = set(identities)
    if not ids:
        return {"status": "unverified", "reason": "No GA4 property is registered", "properties": []}
    token = _google_token(product, root)
    results = []
    for identifier in sorted(ids):
        _identifier(identifier, r"[0-9]+")
        try:
            metadata = _json_api("https://analyticsadmin.googleapis.com/v1beta/properties/" + identifier, token)
            if metadata.get("name") != "properties/" + identifier:
                raise WorkbenchError("identity", "GA4 property identity mismatch")
            try:
                today = dt.datetime.now(ZoneInfo(metadata["timeZone"])).date()
            except (KeyError, ZoneInfoNotFoundError, TypeError):
                raise WorkbenchError("identity", "GA4 reporting timezone is unavailable") from None
            start, end = (today - dt.timedelta(days=days)).isoformat(), (today - dt.timedelta(days=1)).isoformat()
            value = _json_api("https://analyticsdata.googleapis.com/v1beta/properties/" + identifier + ":runReport",
                              token, {"dateRanges": [{"startDate": start, "endDate": end}],
                                      "dimensions": [{"name": "date"}, {"name": "appVersion"}],
                                      "metrics": [{"name": "activeUsers"}, {"name": "sessions"},
                                                  {"name": "eventCount"}, {"name": "totalRevenue"}], "limit": 10000})
            results.append({"property_id": identifier, "status": "ready", "timezone": metadata.get("timeZone"),
                            "currency": metadata.get("currencyCode"), "date_range": {"days": days, "start": start, "end": end},
                            "source_identity": identities[identifier],
                            "report": value, "has_data": bool(value.get("rows")),
                            "note": "Active users are non-additive; revenue missing rows are unknown, not zero. Event instrumentation needs product validation."})
        except WorkbenchError as error:
            results.append({"property_id": identifier, "source_identity": identities[identifier], "status": "unverified", "reason": error.message})
    return {"status": "ready" if all(r["status"] == "ready" for r in results) else "partial", "properties": results}


def _apple_identity(token, app_id, bundle_id):
    app_id = _identifier(app_id, r"[0-9]+")
    value = _json_api("https://api.appstoreconnect.apple.com/v1/apps/" + app_id, token).get("data", {})
    if str(value.get("id")) != app_id or value.get("attributes", {}).get("bundleId") != bundle_id:
        raise WorkbenchError("identity", "App Store target identity mismatch")
    return value


def _sales(raw, app_id, sku):
    if raw[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            raw = compressed.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            raise WorkbenchError("report", "Apple sales report expanded size exceeds limit")
    reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")), delimiter="\t")
    required = {"SKU", "Apple Identifier", "Units", "Developer Proceeds", "Currency of Proceeds"}
    if not required.issubset(set(reader.fieldnames or [])):
        raise WorkbenchError("report", "Apple sales report lacks required columns")
    currencies, matched = {}, 0
    downloads, download_rows, paid_rows, free_rows = decimal.Decimal(0), 0, 0, 0
    unknown_currency, unknown_proceeds, ambiguous_parent = 0, 0, 0
    for row in reader:
        fields = {key: (value or "").strip() for key, value in row.items() if isinstance(key, str)}
        app_row = fields.get("Apple Identifier") == app_id or fields.get("SKU") == sku
        if not app_row and fields.get("Parent Identifier") != sku:
            # Vendor-wide unattributed rows are NOT attributed to this App. They
            # only mark the inability to prove that its proceeds coverage is full.
            kind = fields.get("Product Type Identifier", "")
            if not fields.get("Parent Identifier") and (kind.startswith("IA") or not kind):
                ambiguous_parent += 1
            continue
        matched += 1
        try:
            units = decimal.Decimal(fields["Units"])
            if not units.is_finite():
                raise decimal.InvalidOperation()
        except decimal.InvalidOperation:
            unknown_proceeds += 1
            continue
        if app_row:
            download_rows += 1
            downloads += units
        currency = fields["Currency of Proceeds"].upper()
        if not re.fullmatch(r"[A-Z]{3}", currency):
            unknown_currency += 1
            unknown_proceeds += 1
            continue
        try:
            proceeds = decimal.Decimal(fields["Developer Proceeds"])
            if not proceeds.is_finite():
                raise decimal.InvalidOperation()
        except decimal.InvalidOperation:
            unknown_proceeds += 1
            continue
        amount = units * proceeds
        paid_rows += int(amount != 0)
        free_rows += int(amount == 0)
        currencies[currency] = currencies.get(currency, decimal.Decimal(0)) + amount
    complete = bool(matched and currencies) and not unknown_proceeds and not ambiguous_parent
    return {"proceeds_by_currency": {key: str(value) for key, value in currencies.items()},
            "matched_rows": matched, "revenue_known": complete, "revenue_coverage": "complete" if complete else "partial" if currencies else "unknown",
            "app_download_rows": download_rows, "app_download_units": str(downloads) if download_rows else None,
            "paid_rows": paid_rows, "free_rows": free_rows, "unknown_currency_rows": unknown_currency,
            "unknown_proceeds_rows": unknown_proceeds, "vendor_ambiguous_parent_rows": ambiguous_parent,
            "source_app_filter": {"app_id": app_id, "sku": sku},
            "sha256": hashlib.sha256(raw).hexdigest(), "metric": "units * developer proceeds; not gross revenue"}


def _apple(product, root, days):
    apps = product.get("app_store_apps", [])
    if not apps:
        return {"status": "unverified", "reason": "No App Store target registered", "apps": []}
    token, credential = _apple_token(product, root)
    results = []
    for entry in apps:
        try:
            app = _apple_identity(token, str(entry["app_store_id"]), entry["bundle_id"])
            item = {"app_id": app["id"], "bundle_id": entry["bundle_id"], "status": "ready",
                    "attributes": app.get("attributes", {}), "sales": [], "sales_status": "unverified"}
            # Collect each requested date, independently. Apple may not yet have yesterday's report.
            vendor = credential.get("vendor_number")
            if vendor and app.get("attributes", {}).get("sku"):
                sku = app["attributes"]["sku"]
                for offset in range(1, days + 1):
                    date = (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=offset)).isoformat()
                    query = urllib.parse.urlencode({"filter[frequency]": "DAILY", "filter[reportDate]": date,
                              "filter[reportType]": "SALES", "filter[reportSubType]": "SUMMARY",
                              "filter[vendorNumber]": str(vendor), "filter[version]": "1_0"})
                    code, raw = _request("https://api.appstoreconnect.apple.com/v1/salesReports?" + query, token, accept="application/a-gzip")
                    if code == 200:
                        item["sales"].append({"report_date": date, "status": "ready", **_sales(raw, str(app["id"]), sku)})
                    else:
                        item["sales"].append({"report_date": date, "status": "unverified", "http_status": code})
                item["sales_status"] = "ready" if all(r["status"] == "ready" for r in item["sales"]) else "partial"
            item["status"] = "partial" if item["sales_status"] != "ready" else "ready"
            results.append(item)
        except (WorkbenchError, decimal.InvalidOperation, UnicodeError, ValueError):
            results.append({"app_id": entry.get("app_store_id"), "status": "unverified",
                            "reason": "Apple identity or sales evidence is unavailable"})
    return {"status": "ready" if all(r["status"] == "ready" for r in results) else "partial", "apps": results}


def _cf_auth(product, root, target=None):
    credential, path = _credential(product, root, "cloudflare", "cloudflare-api")
    account = str((target or {}).get("account_id") or credential.get("account_id", ""))
    if account != str(credential.get("account_id")):
        raise WorkbenchError("identity", "Cloudflare credential account does not match target")
    _identifier(account, r"[a-fA-F0-9]{32}")
    return path.read_text().strip(), "https://api.cloudflare.com/client/v4/accounts/" + account


def _cloudflare(product, root, days):
    token, base = _cf_auth(product, root)
    values = []
    for target in product.get("cloudflare_workers", []):
        _cf_auth(product, root, target)
        name = _identifier(target["worker_name"])
        try:
            result = _json_api(base + "/workers/scripts/" + name + "/settings", token).get("result", {})
            bindings = [{key: row[key] for key in ("name", "type", "id", "bucket_name", "workflow_name") if key in row}
                        for row in result.get("bindings", [])]
            values.append({"worker_name": name, "status": "ready", "bindings": bindings,
                           "secret_values_backed_up": False})
        except WorkbenchError as error:
            values.append({"worker_name": name, "status": "unverified", "reason": error.message})
    return {"status": "ready" if values and all(v["status"] == "ready" for v in values) else "partial",
            "workers": values, "scope": "Worker settings and resource identity only; no write or traffic validation"}


def _run(argv, cwd=None, env=None, timeout=120, external=False):
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a and "\x00" not in a for a in argv):
        raise WorkbenchError("configuration", "Command must be a nonempty argument list")
    scan_sensitive(argv)
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "uncertain" if external else "failed", "reason": "Command timed out; reconcile before retry"}
    except OSError:
        return {"status": "failed", "reason": "Command executable or working directory unavailable"}
    # Never return raw output: signed URLs and unknown custom secrets cannot be
    # reliably enumerated. Digest + exit code is sufficient execution evidence.
    return {"status": "succeeded" if result.returncode == 0 else ("uncertain" if external else "failed"),
            "exit_code": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(), "_stdout": result.stdout}


def _legacy(product, root, days):
    configuration = product.get("legacy_ops", {})
    target = next((row for row in product.get("workflow", {}).get("targets", product.get("targets", []))
                   if row.get("legacy_ops_home") and row.get("legacy_repository")), {})
    if not configuration:
        configuration = {"repository": target.get("legacy_repository", "/nonexistent"),
                         "home": target.get("legacy_ops_home", "/nonexistent")}
    repository = Path(configuration.get("repository", "/nonexistent"))
    home = Path(configuration.get("home", "/nonexistent"))
    if not (repository / "scripts/ops_api.py").is_file() or not (home / "config.yaml").is_file():
        return {"status": "unverified", "reason": "Legacy collector is not configured"}
    if target:
        registered, _ = _repository(product, target)
        if registered != repository.resolve():
            raise WorkbenchError("identity", "Legacy collector source differs from registered repository")
    code = ("import sys,json;sys.path.insert(0,sys.argv[1]);import ops_api;"
            "payload,status=ops_api.run(write_evidence=False,quiet=True);"
            "print(json.dumps(payload));sys.exit(status)")
    environment = dict(os.environ, CALORIE_OPS_HOME=str(home))
    result = _run([sys.executable, "-c", code, str(repository / "scripts")], env=environment, timeout=300)
    try:
        data = json.loads(result.pop("_stdout", b""))
        data = safe_json(data)
        return {"status": "ready" if result["status"] == "succeeded" else "partial", "data": data,
                "scope": "Existing CalorieSnapshot read-only collector, no legacy evidence mutation"}
    except (ValueError, WorkbenchError):
        return {"status": "unverified", "reason": "Legacy collector failed or returned unsafe evidence"}


def collect_product(product, root, sources, days=28):
    if not 1 <= days <= 90:
        raise WorkbenchError("configuration", "Collection window must be between 1 and 90 days")
    handlers = {"ga4": _ga4, "apple": _apple, "cloudflare": _cloudflare, "legacy": _legacy}
    rows = []
    for source in dict.fromkeys(sources):
        if source not in handlers:
            raise WorkbenchError("configuration", "Unknown collection source")
        try:
            data = handlers[source](product, Path(root), days)
            rows.append({"source": source, "status": data.get("status", "unverified"), "checked_at": now(), "data": safe_json(data)})
        except Exception as error:
            reason = error.message if isinstance(error, WorkbenchError) else "Collection failed (%s)" % type(error).__name__
            rows.append({"source": source, "status": "unverified", "checked_at": now(), "reason": reason})
    return {"sources": rows, "days": days, "status": "ready" if rows and all(r["status"] == "ready" for r in rows) else "partial"}


def _repository(product, target, candidate=None):
    reference = target.get("repository")
    entries = [entry for entry in product.get("repositories", [])
               if reference in (entry.get("name"), entry.get("id"), entry.get("owner", "") + "/" + entry.get("name", ""))]
    if len(entries) != 1:
        raise WorkbenchError("identity", "Target repository is not uniquely registered")
    entry = entries[0]
    location = (candidate or {}).get("local_path") or entry.get("local_path")
    if not location:
        raise WorkbenchError("configuration", "Repository local checkout is not configured")
    path = Path(location).expanduser().resolve()
    slug = entry["owner"] + "/" + entry["name"]
    origin = _run(["git", "remote", "get-url", "origin"], path)
    value = origin.pop("_stdout", b"").decode(errors="replace").strip()
    valid = {"https://github.com/" + slug, "https://github.com/" + slug + ".git",
             "git@github.com:" + slug, "git@github.com:" + slug + ".git"}
    if origin["status"] != "succeeded" or value not in valid:
        raise WorkbenchError("identity", "Git origin does not match registered repository")
    if candidate is not None:
        if candidate.get("repository") not in (reference, slug, entry["name"], entry.get("id")):
            raise WorkbenchError("identity", "Candidate belongs to a different repository")
        commit = candidate.get("commit", "")
        if not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise WorkbenchError("identity", "Candidate requires a full Git commit")
        current = _run(["git", "rev-parse", "HEAD"], path).pop("_stdout", b"").decode().strip()
        dirty = _run(["git", "status", "--porcelain", "--untracked-files=all"], path)
        if current != commit or dirty["status"] != "succeeded" or dirty.pop("_stdout", b"").strip():
            raise WorkbenchError("identity", "Candidate checkout is changed or not clean")
    return path, slug


def inspect_product(product, root):
    checks = []
    for target in product.get("workflow", {}).get("targets", product.get("targets", [])):
        try:
            path, slug = _repository(product, target)
            status, reason = "ready", "Registered Git identity matches checkout"
        except WorkbenchError as error:
            status, reason = "blocked", error.message
        checks.append({"capability": "repository", "target": target.get("id"), "status": status,
                       "reason": reason, "checked_at": now()})
        for action, field in (("check", "checks"), ("archive", "archive_argv"), ("deploy", "deploy_argv")):
            if action == "archive" and target.get("kind") != "ios":
                continue
            if action == "deploy" and target.get("kind") not in ("web", "worker"):
                continue
            value = target.get(field)
            commands = [row.get("argv", []) for row in value] if field == "checks" and value else [value] if value else []
            missing = any(not argv or not shutil.which(argv[0]) for argv in commands)
            checks.append({"capability": action, "target": target.get("id"),
                           "status": "blocked" if missing else "unverified",
                           "reason": "Required command executable unavailable" if missing else "Configured; execution not tested" if value else "Entry point not configured",
                           "checked_at": now()})
    for note in product.get("readiness_notes", []):
        checks.append({"capability": "product_readiness", "target": product["id"], "status": "unverified",
                       "reason": note, "checked_at": now()})
    return checks


def _safe_result(result):
    result.pop("_stdout", None)
    return safe_json(result)


def _wrangler_identity(path, target):
    path = Path(path).resolve()
    config = target.get("source_configuration") or target.get("wrangler_config")
    if not config:
        raise WorkbenchError("configuration", "A concrete Wrangler configuration is required")
    file = (path / config).resolve()
    if not file.is_relative_to(path) or not file.is_file():
        raise WorkbenchError("identity", "Wrangler configuration must belong to candidate repository")
    text = file.read_text()
    try:
        if file.suffix == ".toml":
            import tomllib
            value = tomllib.loads(text)
        else:
            # Preserve strings while removing comments. Read top-level identity,
            # never an env override or a commented-out former configuration.
            cleaned = re.sub(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*[\s\S]*?\*/',
                             lambda m: m.group(0) if m.group(0).startswith('"') else "", text)
            cleaned = re.sub(r'"(?:\\.|[^"\\])*"|,\s*(?=[}\]])',
                             lambda m: m.group(0) if m.group(0).startswith('"') else "", cleaned)
            value = json.loads(cleaned)
    except (ValueError, ImportError):
        raise WorkbenchError("configuration", "Wrangler configuration cannot be parsed") from None
    if value.get("name") != target.get("worker_name"):
        raise WorkbenchError("identity", "Wrangler worker name differs from registered target")
    account = value.get("account_id")
    if account and account != target.get("account_id"):
        raise WorkbenchError("identity", "Wrangler account differs from registered target")
    return str(file)


def _configured_command(target, field):
    argv = target.get(field)
    if not isinstance(argv, list) or not argv:
        raise WorkbenchError("configuration", "Required product action command is not configured")
    return list(argv)


def _github(path, slug, action, candidate, parameters):
    branch = _run(["git", "branch", "--show-current"], path).pop("_stdout", b"").decode().strip()
    if not branch or branch in ("main", "master"):
        raise WorkbenchError("identity", "A candidate branch is required for PR delivery")
    _identifier(branch, r"[A-Za-z0-9_./-]+")
    # Verify pushed branch against authenticated GitHub, never silently push here.
    remote = _run(["gh", "api", "repos/" + slug + "/git/ref/heads/" + urllib.parse.quote(branch, safe="/")], path)
    try:
        pushed = json.loads(remote.pop("_stdout", b""))["object"]["sha"]
    except (ValueError, KeyError):
        raise WorkbenchError("identity", "Remote candidate branch could not be verified") from None
    if pushed != candidate["commit"]:
        raise WorkbenchError("identity", "Remote branch does not match candidate commit")
    if action == "pr":
        title, body_file = parameters.get("title"), parameters.get("body_file")
        if not isinstance(title, str) or not title or not body_file or not Path(body_file).is_file():
            raise WorkbenchError("configuration", "PR requires a title and saved description file")
        scan_sensitive(title)
        scan_sensitive(Path(body_file).read_text())
        existing = _run(["gh", "pr", "list", "--repo", slug, "--head", branch, "--state", "open", "--json", "number,headRefOid,url"], path)
        try:
            rows = json.loads(existing.pop("_stdout", b""))
        except ValueError:
            raise WorkbenchError("remote", "PR discovery failed") from None
        if len(rows) > 1:
            raise WorkbenchError("identity", "Multiple candidate pull requests found")
        if rows and rows[0].get("headRefOid") != candidate["commit"]:
            raise WorkbenchError("identity", "Existing PR does not match candidate commit")
        argv = ["gh", "pr", "edit", str(rows[0]["number"]), "--repo", slug] if rows else ["gh", "pr", "create", "--repo", slug, "--head", branch]
        result = _run(argv + ["--title", title, "--body-file", str(Path(body_file).resolve())], path, external=True)
        if result["status"] == "succeeded":
            reread = _run(["gh", "pr", "list", "--repo", slug, "--head", branch, "--state", "open", "--json", "number,headRefOid,url"], path)
            try:
                row = json.loads(reread.pop("_stdout", b""))[0]
                if row["headRefOid"] != candidate["commit"]:
                    raise ValueError()
                result.update(remote_id=str(row["number"]), evidence={"url": row["url"], "head_commit": row["headRefOid"]})
            except (ValueError, KeyError, IndexError):
                result.update(status="uncertain", reason="PR write needs remote reconciliation")
        return _safe_result(result)
    number = _identifier(parameters.get("pr_number", ""), r"[0-9]+")
    detail = _run(["gh", "pr", "view", number, "--repo", slug, "--json", "headRefOid,state,url"], path)
    try:
        row = json.loads(detail.pop("_stdout", b""))
    except ValueError:
        raise WorkbenchError("remote", "PR identity could not be verified") from None
    if row.get("headRefOid") != candidate["commit"] or row.get("state") != "OPEN":
        raise WorkbenchError("identity", "PR is not an open exact-candidate PR")
    result = _run(["gh", "pr", "merge", number, "--repo", slug, "--merge", "--match-head-commit", candidate["commit"]], path, external=True)
    result.update(remote_id=number, evidence={"url": row["url"], "head_commit": candidate["commit"]})
    return _safe_result(result)


def execute_action(action, product, root, target, candidate, parameters):
    root = Path(root)
    allowed = {"check", "pr", "merge", "deploy", "smoke", "rollback", "archive", "upload_tf", "prepare_store", "reconcile"}
    if action not in allowed:
        raise WorkbenchError("action", "Unsupported action; store submission and release are excluded")
    if action == "reconcile":
        return _reconcile(product, root, target, candidate, parameters)
    path, slug = _repository(product, target, candidate)
    if action in ("pr", "merge"):
        return _github(path, slug, action, candidate, parameters)
    if action == "check":
        matches = [row for row in target.get("checks", []) if row.get("id") == parameters.get("check") or row.get("id") == parameters.get("name")]
        if len(matches) != 1:
            raise WorkbenchError("configuration", "Selected check is not uniquely configured")
        return _safe_result(_run(matches[0]["argv"], path, timeout=matches[0].get("timeout", 300)))
    if action == "smoke":
        url = target.get("smoke_url")
        if not url or urllib.parse.urlsplit(url).username or urllib.parse.urlsplit(url).password:
            raise WorkbenchError("configuration", "An HTTPS smoke URL without credentials is required")
        code, raw = _request(url)
        expected = target.get("smoke_status", 200)
        return {"status": "succeeded" if code == expected else "failed", "evidence": {"url": url, "http_status": code, "body_sha256": hashlib.sha256(raw).hexdigest()}}
    if action == "deploy":
        token, base = _cf_auth(product, root, target)
        config = _wrangler_identity(path, target)
        # Force a single, verified Wrangler target; shell/npm aliases could deploy elsewhere.
        argv = _configured_command(target, "deploy_argv")
        if (argv[:2] != ["wrangler", "deploy"] and argv[:4] != ["npx", "--no-install", "wrangler", "deploy"]
                and argv[:4] != ["pnpm", "exec", "wrangler", "deploy"]):
            raise WorkbenchError("configuration", "Worker deploy must use explicit wrangler deploy")
        prefix = 2 if argv[0] == "wrangler" else 4
        tail = argv[prefix:]
        if tail and (len(tail) != 2 or tail[0] != "--config"):
            raise WorkbenchError("identity", "Only the verified config argument is permitted for deployment")
        if tail:
            supplied = Path(tail[1])
            if (path / supplied).resolve() != Path(config):
                raise WorkbenchError("identity", "Deployment config differs from verified config")
        else:
            argv += ["--config", config]
        argv += ["--message", "AppWorkbench candidate " + candidate["commit"]]
        if target.get("rollback_policy") != "previous_active_version":
            return {"status": "unverified", "reason": "Registered previous-version rollback policy is required before deployment"}
        captured = deployment_preflight(product, root, target)
        previous, rollback_version = captured["previous_deployment"], captured["rollback_version_id"]
        recorded = parameters.get("deployment_preflight")
        if (not recorded or recorded.get("rollback_version_id") != rollback_version
                or recorded.get("previous_deployment", {}).get("id") != previous.get("id")):
            return {"status": "unverified", "reason": "Durably recorded rollback preflight is missing or the active deployment changed"}
        environment = dict(os.environ, CLOUDFLARE_API_TOKEN=token, CLOUDFLARE_ACCOUNT_ID=target["account_id"])
        result = _run(argv, path, environment, 600, external=True)
        result["rollback_version_id"] = rollback_version
        result["previous_deployment"] = previous
        if result["status"] == "succeeded":
            try:
                remote = _reconcile(product, root, target, candidate, {"action": "deploy"})
            except WorkbenchError:
                remote = {"status": "unverified"}
            if remote["status"] != "succeeded":
                result.update(status="uncertain", reason="Worker version requires authenticated reconciliation")
            else:
                result.update(remote_id=remote["remote_id"], evidence=remote["evidence"])
        return _safe_result(result)
    if action == "rollback":
        token, base = _cf_auth(product, root, target)
        _wrangler_identity(path, target)
        version = _identifier(parameters.get("version_id", ""), r"[a-fA-F0-9-]{36}")
        name = _identifier(target["worker_name"])
        exists = _json_api(base + "/workers/scripts/" + name + "/versions/" + version, token).get("result", {})
        if exists.get("id") != version:
            raise WorkbenchError("identity", "Rollback version does not belong to Worker")
        try:
            value = _json_api(base + "/workers/scripts/" + name + "/deployments", token,
                              {"strategy": "percentage", "versions": [{"version_id": version, "percentage": 100}]})
            verified = _reconcile(product, root, target, candidate, {"action": "rollback", "version_id": version})
            if verified["status"] != "succeeded":
                return {"status": "uncertain", "reason": "Rollback version is not yet verified active"}
            verified["remote_id"] = value.get("result", {}).get("id")
            return verified
        except WorkbenchError:
            return {"status": "uncertain", "reason": "Rollback needs authenticated remote reconciliation"}
    if action == "archive":
        if target.get("kind") != "ios":
            raise WorkbenchError("configuration", "Archive target must be iOS")
        argv = _configured_command(target, "archive_argv")
        if argv[0] != "xcodebuild" or "archive" not in argv:
            raise WorkbenchError("configuration", "Archive must use explicit xcodebuild archive")
        def argument(command, flag):
            if command.count(flag) != 1 or command.index(flag) + 1 >= len(command):
                raise WorkbenchError("configuration", "Archive arguments need unique registered identity and output paths")
            return command[command.index(flag)+1]
        flag = "-workspace" if target.get("workspace") else "-project"
        other = "-project" if flag == "-workspace" else "-workspace"
        project = target.get("workspace") or target.get("project")
        expected_project = (path / (project or "/nonexistent")).resolve()
        if (not project or not expected_project.is_relative_to(path) or not expected_project.exists()
                or other in argv or (path / argument(argv, flag)).resolve() != expected_project
                or argument(argv, "-scheme") != target.get("scheme")):
            raise WorkbenchError("identity", "Archive project and scheme must belong to the committed candidate")
        base_archive = (path / target.get("archive_path", "/nonexistent")).absolute()
        if (path / argument(argv, "-archivePath")).absolute() != base_archive:
            raise WorkbenchError("identity", "Archive command output differs from the registered archive")
        suffix = _identifier(parameters.get("archive_suffix", ""))
        archive = base_archive.with_name(base_archive.stem + "-" + suffix + ".xcarchive")
        if archive.exists() or archive.is_symlink() or any(p.is_symlink() for p in archive.parents):
            raise WorkbenchError("artifact", "Archive must be a fresh output with no symlink parents")
        archive.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        argv[argv.index("-archivePath")+1] = str(archive)
        result = _run(argv, path, timeout=target.get("archive_timeout", 1800))
        if result["status"] == "succeeded":
            info = archive / "Info.plist"
            try:
                identity = plistlib.loads(info.read_bytes())["ApplicationProperties"]
                if (identity.get("CFBundleIdentifier") != target.get("bundle_id")
                        or str(identity.get("CFBundleShortVersionString")) != str(candidate.get("version"))
                        or str(identity.get("CFBundleVersion")) != str(candidate.get("build"))):
                    raise ValueError()
                result["evidence"] = {"commit": candidate["commit"], "archive_path": str(archive), "info_sha256": sha256_file(info),
                                      "bundle_id": identity["CFBundleIdentifier"], "version": identity.get("CFBundleShortVersionString"), "build": identity.get("CFBundleVersion")}
            except (OSError, ValueError, KeyError):
                result.update(status="failed", reason="Fresh archive product identity could not be verified")
        if result["status"] == "succeeded" and target.get("export_argv"):
            argv = _configured_command(target, "export_argv")
            if argv[0] != "xcodebuild" or "-exportArchive" not in argv:
                raise WorkbenchError("configuration", "IPA export must use explicit xcodebuild -exportArchive")
            if (path / argument(argv, "-archivePath")).absolute() != base_archive:
                raise WorkbenchError("identity", "IPA export must reference the registered archive")
            base_ipa = (path / target.get("ipa_path", "/nonexistent")).absolute()
            base_export = (path / argument(argv, "-exportPath")).absolute()
            if base_ipa.parent != base_export:
                raise WorkbenchError("identity", "IPA path must belong to the registered export directory")
            export = base_export.with_name(base_export.name + "-" + suffix)
            if export.exists() or export.is_symlink() or any(p.is_symlink() for p in export.parents):
                raise WorkbenchError("artifact", "IPA export must use a fresh output directory")
            argv[argv.index("-archivePath")+1] = str(archive)
            argv[argv.index("-exportPath")+1] = str(export)
            exported = _run(argv, path, timeout=target.get("export_timeout", 900))
            result["evidence"]["export"] = _safe_result(exported)
            ipa = export / base_ipa.name
            if exported["status"] != "succeeded" or not ipa.is_file() or ipa.is_symlink():
                result.update(status="failed", reason="Fresh signed IPA export failed")
            else:
                actual = _inspect_ipa(ipa)
                expected = {"bundle_id": target.get("bundle_id"), "team_id": target.get("team_id"),
                            "version": str(candidate.get("version")), "build": str(candidate.get("build"))}
                if actual != expected:
                    raise WorkbenchError("identity", "Exported IPA identity differs from candidate")
                result["evidence"]["artifact"] = {"path": str(ipa), "sha256": sha256_file(ipa), "identity": actual}
        return _safe_result(result)
    # Preserve the mature CalorieSnapshot candidate/business/ledger gates.
    token, _ = _apple_token(product, root)
    _apple_identity(token, str(target.get("app_id", "")), target.get("bundle_id"))
    candidate_file = parameters.get("legacy_candidate_file")
    task_id = parameters.get("legacy_task_id")
    legacy_repo = target.get("legacy_repository")
    home = target.get("legacy_ops_home")
    if not all((candidate_file, task_id, legacy_repo, home)):
        if action == "upload_tf":
            return _upload_ipa(product, root, target, candidate, token)
        return _prepare_store(product, root, target, candidate, token, parameters)
    from .security import read_json
    saved = read_json(candidate_file)
    if saved.get("commit") != candidate["commit"] or Path(saved.get("checkout", "")).resolve() != path:
        raise WorkbenchError("identity", "Legacy candidate does not match current candidate")
    expected = {"app_id": str(target.get("app_id")), "bundle_id": target.get("bundle_id"), "team_id": target.get("team_id"), "version": str(candidate.get("version")), "build": str(candidate.get("build"))}
    if any(str(saved.get(k)) != str(v) for k,v in expected.items()):
        raise WorkbenchError("identity", "Legacy candidate App, team, version and build must match the engine candidate")
    artifact = candidate.get("artifact", {})
    ipa = Path(saved.get("ipa", "/nonexistent"))
    if (not artifact.get("sha256") or saved.get("ipa_sha256") != artifact["sha256"]
            or not ipa.is_file() or ipa.is_symlink() or sha256_file(ipa) != artifact["sha256"]):
        raise WorkbenchError("artifact", "Legacy IPA must match the actual engine archive artifact")
    actual = _inspect_ipa(ipa)
    if any(actual.get(k) != expected[k] for k in ("bundle_id", "team_id", "version", "build")):
        raise WorkbenchError("identity", "Legacy IPA distribution signing or identity differs")
    if action == "prepare_store":
        if (Path(parameters.get("metadata_file", "/nonexistent")).resolve() != Path(candidate_file).resolve()
                or parameters.get("metadata_sha256") != sha256_file(Path(candidate_file))):
            raise WorkbenchError("artifact", "Legacy formal preparation requires human review of this exact candidate metadata document")
    legacy_config = json.loads((Path(home) / "config.yaml").read_text())
    if not (path / "scripts/ops.py").is_file() or not (path / "scripts/ops_release.py").is_file():
        raise WorkbenchError("configuration", "Candidate repository lacks the legacy release facility")
    if str(legacy_config["app"]["app_store_id"]) != str(target["app_id"]) or legacy_config["app"]["bundle_id"] != target["bundle_id"]:
        raise WorkbenchError("identity", "Legacy release profile belongs to another App")
    stage = "tf" if action == "upload_tf" else "release"
    argv = [sys.executable, str(path / "scripts/ops.py"), "prepare-release", "--candidate", str(Path(candidate_file).resolve()),
            "--task-id", str(task_id), "--stage", stage, "--execute"]
    result = _run(argv, path, dict(os.environ, CALORIE_OPS_HOME=str(home)), 1800, external=True)
    try:
        evidence = safe_json(json.loads(result.pop("_stdout", b"")))
        result["evidence"] = evidence
    except (ValueError, WorkbenchError):
        result.update(status="uncertain", reason="Legacy preparation result requires remote reconciliation")
    return _safe_result(result)


def _worker_versions(product, root, target):
    token, base = _cf_auth(product, root, target)
    name = _identifier(target["worker_name"])
    result = _json_api(base + "/workers/scripts/" + name + "/versions", token).get("result", {})
    return result.get("items", []) if isinstance(result, dict) else result


def _active_deployment(product, root, target):
    token, base = _cf_auth(product, root, target)
    name = _identifier(target["worker_name"])
    value = _json_api(base + "/workers/scripts/" + name + "/deployments", token).get("result", {})
    rows = value.get("deployments", []) if isinstance(value, dict) else value
    return rows[0] if rows else {}


def deployment_preflight(product, root, target):
    """Read under the engine publisher lock and persist before external dispatch."""
    if target.get("rollback_policy") != "previous_active_version":
        raise WorkbenchError("configuration", "Previous-active-version rollback policy is required")
    active = _active_deployment(product, Path(root), target)
    versions = active.get("versions", [])
    if len(versions) != 1 or versions[0].get("percentage") != 100 or not versions[0].get("version_id") or not active.get("id"):
        raise WorkbenchError("identity", "A unique active 100% Worker deployment is required for safe rollback")
    # Only identifiers and percentages are needed, never annotations/plain values.
    return {"authenticated": True, "rollback_version_id": versions[0]["version_id"],
            "previous_deployment": {"id": active["id"], "versions": [{"version_id": versions[0]["version_id"], "percentage": 100}]}}


def _inspect_ipa(path):
    """Validate the actual application, signed entitlements and store profile."""
    with tempfile.TemporaryDirectory(prefix="wb-ipa-") as temporary:
        destination = Path(temporary)
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = [row.filename for row in members if re.fullmatch(r"Payload/[^/]+\.app/Info.plist", row.filename)]
            if len(names) != 1 or sum(row.file_size for row in members) > 8 * 1024 ** 3:
                raise WorkbenchError("artifact", "IPA application layout or size is invalid")
            for row in members:
                if (Path(row.filename).is_absolute() or ".." in Path(row.filename).parts or "\\" in row.filename
                        or (row.external_attr >> 16) & 0o170000 == 0o120000):
                    raise WorkbenchError("artifact", "IPA contains unsafe paths or symlinks")
            archive.extractall(destination)
        app = destination / Path(names[0]).parent
        info = plistlib.loads((app / "Info.plist").read_bytes())
        profile_result = _run(["security", "cms", "-D", "-i", str(app / "embedded.mobileprovision")])
        if profile_result["status"] != "succeeded":
            raise WorkbenchError("signing", "Embedded distribution profile cannot be decoded")
        profile = plistlib.loads(profile_result.pop("_stdout", b""))
        entitlements = profile.get("Entitlements", {})
        expiry = profile.get("ExpirationDate")
        if (entitlements.get("get-task-allow", True) or profile.get("ProvisionedDevices")
                or profile.get("ProvisionsAllDevices") or not isinstance(expiry, dt.datetime)
                or expiry.replace(tzinfo=dt.timezone.utc) <= dt.datetime.now(dt.timezone.utc)):
            raise WorkbenchError("signing", "An unexpired App Store distribution profile is required")
        verified = _run(["codesign", "--verify", "--deep", "--strict", str(app)])
        signed_result = _run(["codesign", "-d", "--entitlements", ":-", str(app)])
        if verified["status"] != "succeeded" or signed_result["status"] != "succeeded":
            raise WorkbenchError("signing", "IPA code signature cannot be verified")
        signed = plistlib.loads(signed_result.pop("_stdout", b""))
        team = signed.get("com.apple.developer.team-identifier")
        bundle = info["CFBundleIdentifier"]
        app_identifier = signed.get("application-identifier")
        if (team not in profile.get("TeamIdentifier", []) or signed.get("get-task-allow", True)
                or app_identifier != team + "." + bundle
                or entitlements.get("application-identifier") != app_identifier):
            raise WorkbenchError("signing", "IPA signed identity does not match distribution profile")
        return {"bundle_id": bundle, "team_id": team, "version": str(info["CFBundleShortVersionString"]),
                "build": str(info["CFBundleVersion"])}


def _builds(token, target, candidate):
    if not candidate.get("build") or not candidate.get("version"):
        raise WorkbenchError("identity", "Candidate version and build are required")
    query = urllib.parse.urlencode({"filter[app]": str(target["app_id"]), "filter[version]": str(candidate["build"]),
                                   "include": "preReleaseVersion", "limit": 200})
    value = _json_api("https://api.appstoreconnect.apple.com/v1/builds?" + query, token)
    versions = {v["id"]: v.get("attributes", {}).get("version") for v in value.get("included", []) if v.get("type") == "preReleaseVersions"}
    return [r for r in value.get("data", []) if versions.get(r.get("relationships", {}).get("preReleaseVersion", {}).get("data", {}).get("id")) == str(candidate["version"])]


def _upload_ipa(product, root, target, candidate, token):
    artifact = candidate.get("artifact", {})
    path = Path(artifact.get("path", "/nonexistent")).expanduser().resolve()
    if not path.is_file() or path.suffix.lower() != ".ipa" or not artifact.get("sha256"):
        return {"status": "unverified", "reason": "A candidate-bound exported IPA and SHA256 are required"}
    digest = sha256_file(path)
    if digest != artifact["sha256"]:
        raise WorkbenchError("artifact", "IPA digest differs from candidate artifact")
    try:
        identity = _inspect_ipa(path)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile):
        raise WorkbenchError("artifact", "IPA identity or distribution signing is invalid") from None
    expected = {"bundle_id": target.get("bundle_id"), "team_id": target.get("team_id"),
                "version": str(candidate.get("version", "")), "build": str(candidate.get("build", ""))}
    if identity != expected:
        raise WorkbenchError("identity", "IPA identity, team or version differs from candidate target")
    credential, key = _credential(product, root, "apple_api", "apple-app-store-connect")
    if credential.get("team_id") != target.get("team_id"):
        raise WorkbenchError("identity", "App Store credential team differs from target team")
    if _builds(token, target, candidate):
        return {"status": "unverified", "reason": "Exact version/build already exists; reconcile existing upload intent instead of uploading again"}
    # Local altool 27.0.5 help confirms these flags. The key path is explicit so
    # repository-local private_keys cannot shadow the selected credential.
    result = _run(["xcrun", "altool", "--upload-app", "-f", str(path), "--api-key", credential["key_id"],
                   "--api-issuer", credential["issuer_id"], "--p8-file-path", str(key), "--output-format", "json"],
                  key.parent, dict(os.environ, API_PRIVATE_KEYS_DIR=str(key.parent)), 3600, external=True)
    result.pop("_stdout", None)
    result["evidence"] = {"ipa_sha256": digest, **identity, "human_install_purchase_restore": "pending"}
    if result["status"] == "succeeded":
        remote = _reconcile(product, root, target, candidate, {"action": "upload_tf"})
        if remote["status"] == "succeeded":
            result.update(remote_id=remote["remote_id"])
            result["evidence"]["remote"] = remote["evidence"]
        else:
            result.update(status="uncertain", reason="Upload completed; exact build processing must be reconciled without reupload")
    return _safe_result(result)


def _store_spec(parameters):
    metadata = parameters.get("metadata_file")
    if not metadata or not Path(metadata).is_file():
        raise WorkbenchError("configuration", "Reviewed store metadata file is required")
    metadata = Path(metadata)
    digest = sha256_file(metadata)
    if parameters.get("metadata_sha256") != digest:
        raise WorkbenchError("artifact", "Store metadata must match its reviewed SHA256")
    data = json.loads(metadata.read_text())
    scan_sensitive(data)
    if parameters.get("legacy_candidate_file"):
        if Path(parameters["legacy_candidate_file"]).resolve() != metadata.resolve() or not isinstance(data.get("metadata"), dict):
            raise WorkbenchError("identity", "Legacy metadata must be its exact reviewed candidate document")
        locales = []
        for locale, attributes in data["metadata"].items():
            screenshots = []
            for image in data.get("screenshots", []):
                if image.get("locale") != locale:continue
                reference = image.get("file", {})
                if not isinstance(reference, dict):
                    raise WorkbenchError("artifact", "Legacy screenshot needs its actual file reference")
                screenshots.append({"file": reference.get("path"), "sha256": reference.get("sha256"), "display_type": image.get("display_type")})
            locales.append({"locale": locale, **attributes, "screenshots": screenshots})
    else:
        locales = data.get("localizations", [])
    if not isinstance(locales, list) or not locales or len({row.get("locale") for row in locales}) != len(locales):
        raise WorkbenchError("configuration", "Store metadata needs unique localizations")
    expected = []
    for row in locales:
        locale = row.get("locale")
        if not isinstance(locale, str) or not locale or not row.get("screenshots"):
            raise WorkbenchError("configuration", "Every reviewed locale needs existing screenshot specifications")
        screenshots = []
        for image in row["screenshots"]:
            file = Path(image.get("file", "/nonexistent")).expanduser()
            if not file.is_absolute():
                file = metadata.parent / file
            if not file.is_file() or image.get("sha256") != sha256_file(file) or not image.get("display_type"):
                raise WorkbenchError("artifact", "Screenshot file, display type and reviewed SHA256 are required")
            checksum = hashlib.md5(file.read_bytes()).hexdigest()
            screenshots.append({"display_type": image["display_type"], "checksum": checksum,
                                "sha256": image["sha256"], "file_size": file.stat().st_size})
        expected.append({"locale": locale, "attributes": {k: v for k, v in row.items() if k in
                        {"description", "keywords", "marketingUrl", "promotionalText", "supportUrl", "whatsNew"}},
                         "screenshots": screenshots})
    return expected, digest


def _store_rows(token, target, candidate):
    query = urllib.parse.urlencode({"filter[versionString]": str(candidate["version"]), "filter[platform]": "IOS", "limit": 200})
    return _json_api("https://api.appstoreconnect.apple.com/v1/apps/" + str(target["app_id"]) +
                     "/appStoreVersions?" + query, token).get("data", [])


def _store_verify(token, target, candidate, spec, digest):
    base = "https://api.appstoreconnect.apple.com/v1"
    rows = _store_rows(token, target, candidate)
    if len(rows) != 1:
        return {"status": "unverified", "authenticated": True, "reason": "No unique exact-version App Store draft found"}
    row = rows[0]
    version_id = row["id"]
    builds = _builds(token, target, candidate)
    if len(builds) != 1 or builds[0].get("attributes", {}).get("processingState") != "VALID" or builds[0].get("attributes", {}).get("expired", True):
        return {"status": "unverified", "authenticated": True, "reason": "Exact unexpired processed build is not verified"}
    draft = _json_api(base + "/appStoreVersions/" + version_id + "?include=build", token).get("data", {})
    attrs = draft.get("attributes", {})
    linked = draft.get("relationships", {}).get("build", {}).get("data", {}) or {}
    if (attrs.get("versionString") != str(candidate["version"]) or attrs.get("platform") != "IOS"
            or attrs.get("releaseType") != "MANUAL" or linked.get("id") != builds[0]["id"]
            or attrs.get("appStoreState") not in ("PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED", "REJECTED", "METADATA_REJECTED")):
        return {"status": "unverified", "authenticated": True, "reason": "Draft identity, editable state, build link or manual release not verified"}
    localizations = _json_api(base + "/appStoreVersions/" + version_id + "/appStoreVersionLocalizations", token).get("data", [])
    evidence = []
    for expected in spec:
        matched = [row for row in localizations if row.get("attributes", {}).get("locale") == expected["locale"]]
        if len(matched) != 1 or any(matched[0].get("attributes", {}).get(key) != value for key, value in expected["attributes"].items()):
            return {"status": "unverified", "authenticated": True, "reason": "Remote localization differs from reviewed metadata"}
        locale = matched[0]
        sets = _json_api(base + "/appStoreVersionLocalizations/" + locale["id"] + "/appScreenshotSets", token).get("data", [])
        locale_evidence = []
        for display_type in sorted({image["display_type"] for image in expected["screenshots"]}):
            wanted = [image for image in expected["screenshots"] if image["display_type"] == display_type]
            found = [row for row in sets if row.get("attributes", {}).get("screenshotDisplayType") == display_type]
            if len(found) != 1:
                return {"status": "unverified", "authenticated": True, "reason": "Reviewed screenshot display set not found uniquely"}
            images = _json_api(base + "/appScreenshotSets/" + found[0]["id"] + "/appScreenshots", token).get("data", [])
            actual = [row.get("attributes", {}) for row in images]
            # Ordered, complete set equality prevents extra stale/unreviewed screenshots.
            if (len(actual) != len(wanted) or any(
                    str(attrs.get("sourceFileChecksum") or "").lower() != image["checksum"]
                    or attrs.get("fileSize") != image["file_size"]
                    or attrs.get("assetDeliveryState", {}).get("state") != "COMPLETE"
                    for attrs, image in zip(actual, wanted))):
                return {"status": "unverified", "authenticated": True, "reason": "Remote screenshot bytes, ordering or delivery state differ from reviewed files"}
            locale_evidence.append({"display_type": display_type, "screenshot_ids": [row["id"] for row in images],
                                    "sha256": [image["sha256"] for image in wanted]})
        evidence.append({"locale": expected["locale"], "localization_id": locale["id"], "screenshots": locale_evidence})
    return {"status": "succeeded", "authenticated": True, "remote_id": version_id,
            "evidence": {"authenticated_remote": True, "build_id": builds[0]["id"], "release_type": "MANUAL",
                         "metadata_sha256": digest, "localizations": evidence, "state": "awaiting_manual_submission"}}


def _prepare_store(product, root, target, candidate, token, parameters):
    """Prepare an editable manual-release draft, then verify real remote bytes."""
    try:
        spec, digest = _store_spec(parameters)
    except (WorkbenchError, OSError, ValueError, KeyError) as error:
        return {"status": "unverified", "reason": error.message if isinstance(error, WorkbenchError) else "Store metadata is invalid"}
    builds = _builds(token, target, candidate)
    if len(builds) != 1 or builds[0].get("attributes", {}).get("processingState") != "VALID" or builds[0].get("attributes", {}).get("expired", True):
        return {"status": "unverified", "reason": "A unique processed unexpired TestFlight build is required"}
    base = "https://api.appstoreconnect.apple.com/v1"
    rows = _store_rows(token, target, candidate)
    if len(rows) > 1:
        raise WorkbenchError("identity", "Multiple matching App Store version drafts found")
    if rows and rows[0].get("attributes", {}).get("appStoreState") not in ("PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED", "REJECTED", "METADATA_REJECTED"):
        return {"status": "unverified", "reason": "Matching App Store version is not an editable draft"}
    # This transport verifies existing screenshot uploads; it does not invent or
    # auto-accept new screenshots. Upload them via the verified legacy uploader or
    # user-managed App Store Connect, then reconcile the original durable intent.
    try:
        if not rows:
            created = _json_api(base + "/appStoreVersions", token, {"data": {"type": "appStoreVersions", "attributes": {
                "platform": "IOS", "versionString": str(candidate["version"]), "releaseType": "MANUAL"},
                "relationships": {"app": {"data": {"type": "apps", "id": str(target["app_id"])}}}}})
            row = created["data"]
        else:
            row = rows[0]
        version_id = row["id"]
        _json_api(base + "/appStoreVersions/" + version_id, token, {"data": {"type": "appStoreVersions", "id": version_id,
                  "attributes": {"releaseType": "MANUAL"}}}, "PATCH")
        code, _ = _request(base + "/appStoreVersions/" + version_id + "/relationships/build", token,
                            {"data": {"type": "builds", "id": builds[0]["id"]}}, "PATCH")
        if code not in (200, 204):
            raise WorkbenchError("http", "Build linking failed")
        existing = _json_api(base + "/appStoreVersions/" + version_id + "/appStoreVersionLocalizations", token).get("data", [])
        for locale in spec:
            attrs = locale["attributes"]
            found = [row for row in existing if row.get("attributes", {}).get("locale") == locale["locale"]]
            if len(found) > 1:
                raise WorkbenchError("identity", "Duplicate App Store locale")
            if found:
                identifier = found[0]["id"]
                _json_api(base + "/appStoreVersionLocalizations/" + identifier, token,
                          {"data": {"type": "appStoreVersionLocalizations", "id": identifier, "attributes": attrs}}, "PATCH")
            else:
                _json_api(base + "/appStoreVersionLocalizations", token, {"data": {"type": "appStoreVersionLocalizations",
                    "attributes": {"locale": locale["locale"], **attrs}, "relationships": {
                        "appStoreVersion": {"data": {"type": "appStoreVersions", "id": version_id}}}}})
        result = _store_verify(token, target, candidate, spec, digest)
        if result["status"] != "succeeded":
            result["status"] = "uncertain"
            result["reason"] += "; draft mutations started, reconcile before retry"
        return result
    except Exception:
        return {"status": "uncertain", "reason": "Store draft preparation requires remote reconciliation before retry"}


def _reconcile(product, root, target, candidate, parameters):
    previous = parameters.get("original_action") or parameters.get("action")
    if previous == "prepare_store":
        token, _ = _apple_token(product, root)
        _apple_identity(token, str(target.get("app_id", "")), target.get("bundle_id"))
        try:
            spec, digest = _store_spec(parameters)
        except (WorkbenchError, ValueError, OSError):
            return {"status": "unverified", "reason": "Original reviewed store metadata and screenshots are unavailable or changed"}
        return _store_verify(token, target, candidate, spec, digest)
    if previous in ("pr", "merge"):
        path, slug = _repository(product, target)
        number = parameters.get("pr_number") or parameters.get("remote_id")
        if not number:
            lookup = _run(["gh", "pr", "list", "--repo", slug, "--state", "all", "--limit", "100", "--json", "number,headRefOid"], path)
            if lookup["status"] != "succeeded":
                return {"status": "unverified", "reason": "Authenticated PR discovery is unavailable"}
            try:
                rows = [row for row in json.loads(lookup.pop("_stdout", b"")) if row.get("headRefOid") == candidate["commit"]]
            except ValueError:
                rows = []
            if len(rows) != 1:
                return {"status": "unverified", "reason": "No unique exact-candidate PR found for reconciliation"}
            number = str(rows[0]["number"])
        number = _identifier(number, r"[0-9]+")
        result = _run(["gh", "pr", "view", number, "--repo", slug, "--json", "headRefOid,state,url,mergeCommit"], path)
        if result["status"] != "succeeded":
            return {"status": "unverified", "reason": "Authenticated PR remote evidence is unavailable"}
        try:
            value = json.loads(result.pop("_stdout", b""))
            matched = value["headRefOid"] == candidate["commit"]
            matched = matched and (value["state"] == "MERGED" if previous == "merge" else value["state"] in ("OPEN", "MERGED"))
            return {"status": "succeeded" if matched else "unverified", "remote_id": number,
                    "authenticated": True, "evidence": {"authenticated_remote": True, **value}}
        except (ValueError, KeyError):
            return {"status": "unverified", "reason": "PR remote evidence is unavailable"}
    if previous == "smoke":
        active = _reconcile(product, root, target, candidate, {"original_action": "deploy"})
        if active.get("status") != "succeeded" or active.get("authenticated") is not True:
            return {"status": "unverified", "reason": "Candidate is not authenticated as active on the registered Worker"}
        result = execute_action("smoke", product, root, target, candidate, {})
        if result.get("status") in {"succeeded", "failed"}:
            result["authenticated"] = True
            result["evidence"]["deployment"] = active["evidence"]
        return result
    if previous == "deploy":
        values = _worker_versions(product, root, target)
        matching = [v for v in values if v.get("annotations", {}).get("workers/message") == "AppWorkbench candidate " + candidate["commit"]]
        if len(matching) != 1:
            return {"status": "unverified", "reason": "No unique exact-candidate Worker version found"}
        token, base = _cf_auth(product, root, target)
        deployment = _json_api(base + "/workers/scripts/" + _identifier(target["worker_name"]) + "/deployments", token).get("result", {})
        rows = deployment.get("deployments", []) if isinstance(deployment, dict) else deployment
        active = rows[0] if rows else {}
        matched = any(v.get("version_id") == matching[0]["id"] and v.get("percentage") == 100 for v in active.get("versions", []))
        return {"status": "succeeded" if matched else "unverified", "remote_id": matching[0]["id"],
                "rollback_version_id": parameters.get("deployment_preflight", {}).get("rollback_version_id"),
                "previous_deployment": parameters.get("deployment_preflight", {}).get("previous_deployment"),
                "authenticated": True, "evidence": {"authenticated_remote": True, "version": matching[0], "deployment": active}}
    if previous == "rollback":
        token, base = _cf_auth(product, root, target)
        name = _identifier(target["worker_name"])
        version = _identifier(parameters.get("version_id", ""), r"[a-fA-F0-9-]{36}")
        result = _json_api(base + "/workers/scripts/" + name + "/deployments", token).get("result", {})
        rows = result.get("deployments", []) if isinstance(result, dict) else result
        active = rows[0] if rows else {}
        matched = any(v.get("version_id") == version and v.get("percentage") == 100 for v in active.get("versions", []))
        return {"status": "succeeded" if matched else "unverified", "remote_id": active.get("id"),
                "authenticated": True, "evidence": {"authenticated_remote": True, "version_id": version, "deployment": active}}
    if previous == "upload_tf":
        token, _ = _apple_token(product, root)
        _apple_identity(token, str(target.get("app_id", "")), target.get("bundle_id"))
        version, build = candidate.get("version"), candidate.get("build")
        if not version or not build:
            return {"status": "unverified", "reason": "Version and build are required for TestFlight reconciliation"}
        query = urllib.parse.urlencode({"filter[app]": str(target["app_id"]), "filter[version]": str(build), "include": "preReleaseVersion", "limit": 200})
        value = _json_api("https://api.appstoreconnect.apple.com/v1/builds?" + query, token)
        versions = {v["id"]: v.get("attributes", {}).get("version") for v in value.get("included", []) if v.get("type") == "preReleaseVersions"}
        rows = [r for r in value.get("data", []) if versions.get(r.get("relationships", {}).get("preReleaseVersion", {}).get("data", {}).get("id")) == str(version)]
        if (len(rows) == 1 and rows[0].get("attributes", {}).get("processingState") == "VALID"
                and not rows[0].get("attributes", {}).get("expired", True)):
            return {"status": "succeeded", "remote_id": rows[0]["id"], "authenticated": True, "evidence": {"authenticated_remote": True, "build": rows[0], "version": version,
                    "note": "Remote identity verified; Apple does not expose original IPA digest"}}
        return {"status": "unverified", "reason": "Exact App version/build is missing, ambiguous or still processing"}
    return {"status": "unverified", "reason": "This action requires additional authenticated remote evidence"}
