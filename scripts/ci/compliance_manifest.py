"""The site's compliance manifest, validated, and the live site judged by it.

WHY THIS EXISTS. The origin keeps strong privacy properties by construction --
`default-src 'self'`, no cookie of its own, no client address in its logs --
and every one of them is pinned by a Go test against the binary. None of those
tests can see what a visitor actually receives, because an edge sits between
the binary and the visitor and can add headers, scripts and reporting
endpoints of its own. On 2026-10-08 it was doing all three (issue #173). And
nothing kept the facts a privacy notice must state -- what the site stores on
a visitor's device, which third parties a page contacts, which legal pages
exist -- written down in one place a gate could hold the site to.

`compliance.json` at the repository root is that place. This file has two
subcommands, and the browser smoke lanes
(`frontend/tests/browser/compliance.spec.mjs`) read the same manifest:

  check  validate the manifest's closed schema, and refuse a declaration that
         has gone stale in the source: a storage name no frontend file writes,
         or a data-collection entry whose evidence file is gone.
  live   GET the production URL and judge what the edge actually serves: the
         CSP must admit no origin the manifest does not declare (and none at
         all through a wildcard or a bare scheme), script directives must not
         admit inline or eval'd code, framing must be denied, HSTS must last a
         year, nosniff and a Referrer-Policy must be present, the document must
         set no cookie, every reporting endpoint and every script, stylesheet
         or embedded resource in the served HTML must be this origin's or
         declared, and every published legal page must answer 200. A declared
         third party or edge observation that no longer occurs is refused as
         stale, so an exemption never outlives its case.

PIN BEHAVIOUR, NOT INVENTORY. Nothing here asserts "the site has exactly these
headers" or "these are all the scripts". Each rule refuses one construct that
changes what a visitor is exposed to, and a legitimate addition either passes
untouched or needs one declared line.

LIFT. Every refusal prints the exact `compliance.json` entry that would admit
it, and every entry needs a written reason (and, for an edge observation, the
issue that holds the decision). Adding a declared third party is a normal,
reviewed one-line change; it is also exactly the line a privacy notice has to
mention, which is the point.

Logging follows the repository's failure-visibility rule: one START line with
the budget, one line per refusal, one SUMMARY with the decision and duration.
"""

from __future__ import annotations

import argparse
import html.parser
import json
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "compliance.json"
SOURCE_ROOT = ROOT / "frontend" / "src"
SCHEMA = "compliance/v1"

TOP_KEYS = {
    "schema",
    "liveUrl",
    "dataCollected",
    "storage",
    "thirdParties",
    "legalPages",
    "edgeObservations",
}
ENTRY_KEYS = {
    "dataCollected": ({"what", "where", "purpose", "evidence"}, set()),
    "storage": ({"name", "kind", "writtenWhen", "purpose"}, set()),
    "thirdParties": ({"origin", "purpose", "consent", "reason"}, set()),
    "legalPages": ({"id", "status"}, {"path", "decision"}),
    "edgeObservations": ({"kind", "reason", "issue"}, {"marker", "origin"}),
}
STORAGE_KINDS = {"cookie", "localStorage", "sessionStorage"}
# Only a write the visitor causes is admitted. Writing on load is the
# consent question itself; admitting it needs a consent mechanism this site
# does not have, which is a code change and not a manifest line.
WRITTEN_WHEN = {"visitor-action"}
CONSENT = {"not-required"}
PAGE_STATUS = {"published", "pending"}
OBSERVATION_KINDS = {"injected-inline-script", "reporting-endpoint"}
ISSUE_URL = re.compile(r"\Ahttps://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+\Z")
ORIGIN = re.compile(r"\Ahttps://[a-z0-9.-]+(?::[0-9]{1,5})?\Z")

# Fetch directives: every directive that decides where a page may load or
# connect. `default-src` is the fallback for the ones a policy omits.
FETCH_DIRECTIVES = (
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "font-src",
    "connect-src",
    "media-src",
    "object-src",
    "frame-src",
    "child-src",
    "worker-src",
    "manifest-src",
)
SCRIPT_DIRECTIVES = ("default-src", "script-src", "script-src-elem", "script-src-attr")
# Keywords that admit no origin at all. Hash and nonce sources are matched
# separately; they name bytes, not places.
NEUTRAL_KEYWORDS = {"'self'", "'none'", "'report-sample'"}
INLINE_KEYWORDS = {"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "'wasm-unsafe-eval'"}
HASH_OR_NONCE = re.compile(r"\A'(?:sha256|sha384|sha512|nonce)-[A-Za-z0-9+/=_-]+'\Z")
# `data:` and `blob:` name no host. They stay legal where they are ordinary.
SCHEME_SOURCES = {
    "data:": {"img-src", "font-src", "media-src"},
    "blob:": {"img-src", "media-src", "worker-src"},
}
HSTS_FLOOR_SECONDS = 31_536_000
REFERRER_POLICIES = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
FETCH_TIMEOUT_SECONDS = 20
BODY_CAP_BYTES = 2 * 1024 * 1024
USER_AGENT = "compliance-live-check/1 (read-only GET)"
LOADING_LINK_RELS = {
    "stylesheet",
    "preload",
    "modulepreload",
    "preconnect",
    "dns-prefetch",
    "prefetch",
    "icon",
    "apple-touch-icon",
    "manifest",
}
EMBED_TAGS = {"img", "iframe", "embed", "object", "source", "video", "audio", "track"}


@dataclass
class Fetched:
    """One HTTP answer, reduced to what the judge reads."""

    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def all(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def first(self, name: str) -> str | None:
        values = self.all(name)
        return values[0] if values else None


@dataclass
class Verdict:
    refusals: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def refuse(self, message: str, lift: str | None = None) -> None:
        self.refusals.append(message if lift is None else f"{message} (lift: {lift})")


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}".lower()


# ---------------------------------------------------------------- check mode


def _text(value: object) -> bool:
    return isinstance(value, str) and value.strip() != ""


def validate(manifest: object, source_root: Path = SOURCE_ROOT, repo_root: Path = ROOT) -> list[str]:
    """Every way the manifest fails its closed schema or has gone stale."""
    refusals: list[str] = []
    if not isinstance(manifest, dict):
        return ["compliance.json must be one JSON object"]
    keys = set(manifest)
    for missing in sorted(TOP_KEYS - keys):
        refusals.append(f"compliance.json lacks the required key {missing!r}")
    for unknown in sorted(keys - TOP_KEYS):
        refusals.append(f"compliance.json carries the unknown key {unknown!r}; the schema is closed so a typo cannot pass silently")
    if manifest.get("schema") != SCHEMA:
        refusals.append(f"compliance.json schema must be {SCHEMA!r}")
    live = manifest.get("liveUrl")
    if not (isinstance(live, str) and live.startswith("https://") and urlsplit(live).netloc):
        refusals.append("liveUrl must be the site's https:// URL")

    for section, (required, optional) in ENTRY_KEYS.items():
        entries = manifest.get(section)
        if entries is None:
            continue
        if not isinstance(entries, list):
            refusals.append(f"{section} must be a list")
            continue
        for index, entry in enumerate(entries):
            where = f"{section}[{index}]"
            if not isinstance(entry, dict):
                refusals.append(f"{where} must be an object")
                continue
            for missing in sorted(required - set(entry)):
                refusals.append(f"{where} lacks {missing!r}")
            for unknown in sorted(set(entry) - required - optional):
                refusals.append(f"{where} carries the unknown key {unknown!r}")
            for key in sorted(set(entry) & (required | optional)):
                if not _text(entry[key]):
                    refusals.append(f"{where}.{key} must be a non-empty string")

    sources = _source_text(source_root)
    for index, entry in enumerate(_entries(manifest, "dataCollected")):
        evidence = entry.get("evidence")
        if _text(evidence) and not (repo_root / evidence).exists():
            refusals.append(f"dataCollected[{index}].evidence {evidence!r} no longer exists: the entry is stale")

    for index, entry in enumerate(_entries(manifest, "storage")):
        where = f"storage[{index}]"
        if entry.get("kind") not in STORAGE_KINDS:
            refusals.append(f"{where}.kind must be one of {sorted(STORAGE_KINDS)}")
        if entry.get("writtenWhen") not in WRITTEN_WHEN:
            refusals.append(
                f"{where}.writtenWhen must be one of {sorted(WRITTEN_WHEN)}: a write on load needs consent, "
                "and consent needs a mechanism this site does not have"
            )
        name = entry.get("name")
        if _text(name):
            literal = re.compile("[\"'`]" + re.escape(name) + "[\"'`=]")
            if not literal.search(sources):
                refusals.append(f"{where} declares {name!r}, which no file under frontend/src writes: the entry is stale")

    for index, entry in enumerate(_entries(manifest, "thirdParties")):
        where = f"thirdParties[{index}]"
        if not (isinstance(entry.get("origin"), str) and ORIGIN.match(entry["origin"])):
            refusals.append(f"{where}.origin must be a bare https origin such as https://host.example")
        if entry.get("consent") not in CONSENT:
            refusals.append(
                f"{where}.consent must be one of {sorted(CONSENT)}: a third party that needs consent needs "
                "a consent mechanism first, which is a code change"
            )

    seen_ids: set[str] = set()
    for index, entry in enumerate(_entries(manifest, "legalPages")):
        where = f"legalPages[{index}]"
        page_id = entry.get("id")
        if page_id in seen_ids:
            refusals.append(f"{where}.id {page_id!r} is declared twice")
        if isinstance(page_id, str):
            seen_ids.add(page_id)
        status = entry.get("status")
        if status not in PAGE_STATUS:
            refusals.append(f"{where}.status must be one of {sorted(PAGE_STATUS)}")
        if status == "published" and not (isinstance(entry.get("path"), str) and entry["path"].startswith("/")):
            refusals.append(f"{where} is published, so it needs the absolute path it is served at")
        if status == "pending" and not (isinstance(entry.get("decision"), str) and ISSUE_URL.match(entry["decision"])):
            refusals.append(f"{where} is pending, so it needs the issue URL that holds the decision")

    for index, entry in enumerate(_entries(manifest, "edgeObservations")):
        where = f"edgeObservations[{index}]"
        kind = entry.get("kind")
        if kind not in OBSERVATION_KINDS:
            refusals.append(f"{where}.kind must be one of {sorted(OBSERVATION_KINDS)}")
        if kind == "injected-inline-script" and not _text(entry.get("marker")):
            refusals.append(f"{where} needs the marker text that identifies the injected script")
        if kind == "reporting-endpoint" and not (isinstance(entry.get("origin"), str) and ORIGIN.match(entry["origin"])):
            refusals.append(f"{where} needs the bare https origin the reports go to")
        if not (isinstance(entry.get("issue"), str) and ISSUE_URL.match(entry["issue"])):
            refusals.append(f"{where}.issue must be the issue URL that holds the decision")
    return refusals


def _entries(manifest: dict, section: str) -> list[dict]:
    value = manifest.get(section)
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _source_text(source_root: Path) -> str:
    if not source_root.is_dir():
        return ""
    chunks = []
    for path in sorted(source_root.rglob("*")):
        if path.is_file() and path.suffix in {".ts", ".js", ".mjs", ".svelte"}:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


# ----------------------------------------------------------------- live mode


def parse_csp(value: str) -> dict[str, list[str]]:
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        name = tokens[0].lower()
        # The first occurrence of a directive wins (CSP3 section 2.2.1).
        policy.setdefault(name, tokens[1:])
    return policy


class _Resources(html.parser.HTMLParser):
    """Collect every load the served HTML asks a browser to make."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.loads: list[tuple[str, str]] = []
        self.inline_scripts: list[str] = []
        self._inline: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag == "script":
            if values.get("src"):
                self.loads.append(("script", values["src"]))
            else:
                self._inline = []
        elif tag == "link":
            rels = set(values.get("rel", "").lower().split())
            if rels & LOADING_LINK_RELS and values.get("href"):
                self.loads.append(("link " + " ".join(sorted(rels)), values["href"]))
        elif tag in EMBED_TAGS:
            for attribute in ("src", "data", "poster"):
                if values.get(attribute):
                    self.loads.append((tag, values[attribute]))
            for candidate in values.get("srcset", "").split(","):
                url = candidate.strip().split(" ")[0]
                if url:
                    self.loads.append((tag + " srcset", url))

    def handle_data(self, data: str) -> None:
        if self._inline is not None:
            self._inline.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inline is not None:
            body = "".join(self._inline)
            if body.strip():
                self.inline_scripts.append(body)
            self._inline = None


def reporting_origins(document: Fetched) -> set[str]:
    origins: set[str] = set()
    for value in document.all("report-to"):
        try:
            groups = json.loads("[" + value + "]")
        except json.JSONDecodeError:
            origins.add("<unparseable Report-To>")
            continue
        for group in groups:
            for endpoint in group.get("endpoints", []) if isinstance(group, dict) else []:
                url = endpoint.get("url") if isinstance(endpoint, dict) else None
                if isinstance(url, str):
                    origins.add(origin_of(url))
    for value in document.all("reporting-endpoints"):
        for match in re.finditer(r'"([^"]+)"', value):
            origins.add(origin_of(match.group(1)))
    for value in document.all("content-security-policy"):
        for url in parse_csp(value).get("report-uri", []):
            origins.add(origin_of(urljoin(document.url, url)))
    return origins


def judge(manifest: dict, document: Fetched, pages: dict[str, Fetched]) -> Verdict:
    verdict = Verdict()
    site = origin_of(manifest["liveUrl"])
    declared = {entry["origin"].lower() for entry in _entries(manifest, "thirdParties")}
    observations = _entries(manifest, "edgeObservations")
    markers = {entry["marker"]: False for entry in observations if entry.get("kind") == "injected-inline-script"}
    reporters = {
        entry["origin"].lower(): False for entry in observations if entry.get("kind") == "reporting-endpoint"
    }

    if document.status != 200:
        verdict.refuse(
            f"the document answered {document.status}, not 200; an edge challenge or an outage is "
            "not a compliance pass, and the rest of the headers below may not be the site's"
        )

    policies = document.all("content-security-policy")
    referenced: set[str] = set()
    if not policies:
        verdict.refuse("no Content-Security-Policy header: nothing bounds which origins a page may load")
    for raw in policies:
        policy = parse_csp(raw)
        if "default-src" not in policy:
            verdict.refuse("the CSP has no default-src, so every fetch directive it omits admits any origin")
        for directive in FETCH_DIRECTIVES:
            for source in policy.get(directive, []):
                lowered = source.lower()
                if lowered in NEUTRAL_KEYWORDS or HASH_OR_NONCE.match(source):
                    continue
                if lowered in INLINE_KEYWORDS:
                    if directive in SCRIPT_DIRECTIVES:
                        verdict.refuse(f"the CSP {directive} admits {source}, which runs code no file of this repository shipped")
                    continue
                if lowered.startswith("'"):
                    # 'strict-dynamic' and any keyword this judge does not
                    # know: each can widen what loads, so none passes unread.
                    verdict.refuse(f"the CSP {directive} carries {source}, a keyword this gate does not admit")
                    continue
                if lowered in SCHEME_SOURCES:
                    if directive not in SCHEME_SOURCES[lowered]:
                        verdict.refuse(f"the CSP {directive} admits the bare scheme {source}")
                    continue
                if "*" in lowered or lowered.endswith(":"):
                    verdict.refuse(f"the CSP {directive} admits {source}, which names no single origin")
                    continue
                candidate = lowered if "://" in lowered else "https://" + lowered
                candidate = origin_of(candidate)
                referenced.add(candidate)
                if candidate != site and candidate not in declared:
                    verdict.refuse(
                        f"the CSP {directive} admits the undeclared origin {candidate}",
                        f'add to compliance.json thirdParties {{"origin": "{candidate}", "purpose": "...", '
                        '"consent": "not-required", "reason": "..."}',
                    )
        ancestors = policy.get("frame-ancestors")
        if ancestors is not None and set(a.lower() for a in ancestors) - {"'none'", "'self'"}:
            verdict.refuse(f"the CSP frame-ancestors admits {' '.join(ancestors)}")
    framing_denied = any(
        set(a.lower() for a in parse_csp(raw).get("frame-ancestors", ["*"])) <= {"'none'", "'self'"}
        for raw in policies
    ) or (document.first("x-frame-options") or "").strip().upper() in {"DENY", "SAMEORIGIN"}
    if not framing_denied:
        verdict.refuse("neither frame-ancestors nor X-Frame-Options denies framing by other sites")

    for origin in sorted(declared - referenced):
        verdict.refuse(
            f"thirdParties declares {origin}, which the live CSP no longer admits: the entry is stale",
            "delete that thirdParties entry",
        )

    hsts = document.first("strict-transport-security") or ""
    match = re.search(r"max-age\s*=\s*\"?([0-9]+)", hsts, re.IGNORECASE)
    if not match or int(match.group(1)) < HSTS_FLOOR_SECONDS:
        verdict.refuse(f"Strict-Transport-Security must carry max-age >= {HSTS_FLOOR_SECONDS}; got {hsts or 'nothing'}")
    if (document.first("x-content-type-options") or "").strip().lower() != "nosniff":
        verdict.refuse("X-Content-Type-Options: nosniff is missing")
    referrer = [token.strip().lower() for token in (document.first("referrer-policy") or "").split(",") if token.strip()]
    if not referrer or referrer[-1] not in REFERRER_POLICIES:
        verdict.refuse(f"Referrer-Policy must be one of {sorted(REFERRER_POLICIES)}; got {', '.join(referrer) or 'nothing'}")
    for cookie in document.all("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        verdict.refuse(f"the document sets the cookie {name!r} before the visitor has done anything")

    for origin in sorted(reporting_origins(document)):
        if origin == site:
            continue
        if origin in reporters:
            reporters[origin] = True
            verdict.notes.append(f"declared reporting endpoint seen: {origin}")
            continue
        verdict.refuse(
            f"browsers are told to send reports to the undeclared origin {origin}",
            f'add to compliance.json edgeObservations {{"kind": "reporting-endpoint", "origin": "{origin}", '
            '"reason": "...", "issue": "<issue URL>"}',
        )

    resources = _Resources()
    resources.feed(document.body.decode("utf-8", errors="replace"))
    resources.close()
    for kind, url in resources.loads:
        target = urlsplit(urljoin(document.url, url))
        if target.scheme not in {"http", "https"}:
            continue
        origin = origin_of(urljoin(document.url, url))
        if origin != site and origin not in declared:
            verdict.refuse(
                f"the served HTML loads {kind} from the undeclared origin {origin}",
                f'add to compliance.json thirdParties {{"origin": "{origin}", "purpose": "...", '
                '"consent": "not-required", "reason": "..."}',
            )
    for body in resources.inline_scripts:
        hit = next((marker for marker in markers if marker in body), None)
        if hit is None:
            verdict.refuse(
                "the served HTML carries an inline script this repository did not build "
                f"(starts {body.strip()[:60]!r})",
                'add to compliance.json edgeObservations {"kind": "injected-inline-script", "marker": "<text unique '
                'to that script>", "reason": "...", "issue": "<issue URL>"}',
            )
        else:
            markers[hit] = True
            verdict.notes.append(f"declared injected script seen: {hit}")

    for marker, seen in sorted(markers.items()):
        if not seen:
            verdict.refuse(
                f"edgeObservations declares an injected script marked {marker!r} that no longer occurs: the entry is stale",
                "delete that edgeObservations entry",
            )
    for origin, seen in sorted(reporters.items()):
        if not seen:
            verdict.refuse(
                f"edgeObservations declares the reporting endpoint {origin}, which no longer occurs: the entry is stale",
                "delete that edgeObservations entry",
            )

    for entry in _entries(manifest, "legalPages"):
        if entry.get("status") != "published":
            verdict.notes.append(f"legal page {entry.get('id')!r} pending: {entry.get('decision')}")
            continue
        answer = pages.get(entry["path"])
        if answer is None or answer.status != 200:
            status = "no answer" if answer is None else str(answer.status)
            verdict.refuse(f"the published legal page {entry['path']} answered {status}, not 200")
        elif not (answer.first("content-type") or "").lower().startswith("text/html"):
            verdict.refuse(f"the published legal page {entry['path']} is not served as text/html")
    return verdict


def fetch(url: str) -> Fetched:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
            return Fetched(response.geturl(), response.status, list(response.headers.items()), response.read(BODY_CAP_BYTES))
    except urllib.error.HTTPError as error:
        with error:
            return Fetched(url, error.code, list(error.headers.items()), error.read(BODY_CAP_BYTES))


def _log(line: str) -> None:
    print(f"compliance: {line}", flush=True)


def _read(manifest_path: Path) -> tuple[object, list[str]]:
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8")), []
    except (OSError, json.JSONDecodeError) as error:
        return None, [f"cannot read {manifest_path.name}: {error}"]


def run_check(manifest_path: Path) -> int:
    started = time.monotonic()
    _log(f"START mode=check manifest={manifest_path.name}")
    manifest, refusals = _read(manifest_path)
    if not refusals:
        refusals = validate(manifest)
    for refusal in refusals:
        _log(f"REFUSE {refusal}")
    decision = "fail" if refusals else "pass"
    _log(f"SUMMARY mode=check decision={decision} refusals={len(refusals)} duration_ms={int((time.monotonic() - started) * 1000)}")
    return 1 if refusals else 0


def run_live(manifest_path: Path, fetcher=fetch) -> int:
    started = time.monotonic()
    manifest, problems = _read(manifest_path)
    if not problems:
        problems = validate(manifest)
    pages_budget = len(_entries(manifest, "legalPages")) if isinstance(manifest, dict) else 0
    live_url = manifest.get("liveUrl") if isinstance(manifest, dict) else None
    _log(f"START mode=live url={live_url} budget_s={FETCH_TIMEOUT_SECONDS * (1 + pages_budget)}")
    if problems:
        for problem in problems:
            _log(f"REFUSE {problem}")
        _log(f"SUMMARY mode=live decision=fail refusals={len(problems)} duration_ms={int((time.monotonic() - started) * 1000)}")
        return 1
    try:
        document = fetcher(manifest["liveUrl"])
        pages = {
            entry["path"]: fetcher(urljoin(manifest["liveUrl"], entry["path"]))
            for entry in _entries(manifest, "legalPages")
            if entry.get("status") == "published"
        }
    except (OSError, ValueError) as error:
        _log(f"REFUSE the live site could not be read: {error}")
        _log(f"SUMMARY mode=live decision=fail refusals=1 duration_ms={int((time.monotonic() - started) * 1000)}")
        return 1
    verdict = judge(manifest, document, pages)
    for note in verdict.notes:
        _log(f"NOTE {note}")
    for refusal in verdict.refusals:
        _log(f"REFUSE {refusal}")
    decision = "fail" if verdict.refusals else "pass"
    _log(
        f"SUMMARY mode=live decision={decision} refusals={len(verdict.refusals)} "
        f"status={document.status} duration_ms={int((time.monotonic() - started) * 1000)}"
    )
    return 1 if verdict.refusals else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=("check", "live"))
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args(argv)
    if args.command == "check":
        return run_check(args.manifest)
    return run_live(args.manifest)


if __name__ == "__main__":
    sys.exit(main())
