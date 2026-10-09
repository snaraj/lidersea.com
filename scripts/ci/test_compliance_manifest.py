"""Behaviour of `compliance_manifest.py`: one compliant answer passes, and each
construct the gate exists to refuse turns it red on its own.

Every case starts from the same compliant manifest and document and changes
exactly one thing, so a refusal is attributable to that one change and a
passing baseline proves the refusal is not the gate's default answer.
"""

from __future__ import annotations

import http.server
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import compliance_manifest as gate

SITE = "https://site.example/"
REPORTS = "https://reports.example"
MARKER = "/edge-injected/"


def manifest() -> dict:
    return {
        "schema": "compliance/v1",
        "liveUrl": SITE,
        "dataCollected": [
            {"what": "request paths", "where": "pod log", "purpose": "operating the site", "evidence": "evidence.go"}
        ],
        "storage": [
            {"name": "theme", "kind": "cookie", "writtenWhen": "visitor-action", "purpose": "reading mode"},
            {"name": "width", "kind": "localStorage", "writtenWhen": "visitor-action", "purpose": "column width"},
        ],
        "thirdParties": [],
        "legalPages": [{"id": "privacy", "status": "pending", "decision": "https://github.com/owner/site/issues/1"}],
        "edgeObservations": [
            {"kind": "injected-inline-script", "marker": MARKER, "reason": "edge", "issue": "https://github.com/owner/infra/issues/2"},
            {"kind": "reporting-endpoint", "origin": REPORTS, "reason": "edge", "issue": "https://github.com/owner/infra/issues/2"},
        ],
    }


HTML = (
    "<!doctype html><html lang=en><head>"
    '<script type="module" src="/assets/index.js"></script>'
    '<link rel="stylesheet" href="/assets/index.css">'
    '<link rel="icon" href="/favicon.svg">'
    "</head><body><main><a href=\"https://elsewhere.example/\">a link is not a load</a></main>"
    f"<script>(function(){{var s='{MARKER}main.js'}})();</script>"
    "</body></html>"
)


def headers(**overrides: str | None) -> list[tuple[str, str]]:
    base = {
        "Content-Security-Policy": "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Report-To": json.dumps({"group": "edge", "max_age": 60, "endpoints": [{"url": REPORTS + "/report?s=x"}]}),
        "NEL": '{"report_to":"edge","max_age":60}',
        "Content-Type": "text/html; charset=utf-8",
    }
    for key, value in overrides.items():
        base[key.replace("_", "-")] = value
    return [(key, value) for key, value in base.items() if value is not None]


def document(html: str = HTML, status: int = 200, **overrides: str | None) -> gate.Fetched:
    return gate.Fetched(SITE, status, headers(**overrides), html.encode())


class JudgeTests(unittest.TestCase):
    def assertRefused(self, verdict: gate.Verdict, fragment: str) -> None:
        self.assertTrue(
            any(fragment in refusal for refusal in verdict.refusals),
            f"expected a refusal containing {fragment!r}, got {verdict.refusals}",
        )

    def test_the_compliant_baseline_passes(self) -> None:
        verdict = gate.judge(manifest(), document(), {})
        self.assertEqual(verdict.refusals, [])
        self.assertIn(f"declared injected script seen: {MARKER}", verdict.notes)

    def test_a_non_200_document_is_refused(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(status=403), {}), "answered 403")

    def test_a_missing_csp_is_refused(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=None), {}), "no Content-Security-Policy")

    def test_a_csp_without_default_src_is_refused(self) -> None:
        verdict = gate.judge(manifest(), document(Content_Security_Policy="script-src 'self'; frame-ancestors 'none'"), {})
        self.assertRefused(verdict, "no default-src")

    def test_an_undeclared_origin_in_any_fetch_directive_is_refused_with_its_lift(self) -> None:
        for directive in ("script-src", "font-src", "connect-src", "img-src", "style-src", "frame-src"):
            with self.subTest(directive=directive):
                csp = f"default-src 'self'; {directive} 'self' https://cdn.example; frame-ancestors 'none'"
                verdict = gate.judge(manifest(), document(Content_Security_Policy=csp), {})
                self.assertRefused(verdict, f"{directive} admits the undeclared origin https://cdn.example")
                self.assertRefused(verdict, '"origin": "https://cdn.example"')

    def test_a_declared_origin_passes_and_an_unused_declaration_is_stale(self) -> None:
        declared = manifest()
        declared["thirdParties"] = [
            {"origin": "https://cdn.example", "purpose": "fonts", "consent": "not-required", "reason": "self-hosting is planned"}
        ]
        csp = "default-src 'self'; font-src https://cdn.example; frame-ancestors 'none'"
        self.assertEqual(gate.judge(declared, document(Content_Security_Policy=csp), {}).refusals, [])
        self.assertRefused(gate.judge(declared, document(), {}), "https://cdn.example, which the live CSP no longer admits")

    def test_wildcards_and_bare_schemes_are_refused(self) -> None:
        for source, directive, fragment in (
            ("*", "img-src", "names no single origin"),
            ("https:", "connect-src", "names no single origin"),
            ("*.example", "script-src", "names no single origin"),
            ("data:", "script-src", "admits the bare scheme data:"),
        ):
            with self.subTest(source=source):
                csp = f"default-src 'self'; {directive} {source}; frame-ancestors 'none'"
                self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp), {}), fragment)

    def test_data_images_are_ordinary(self) -> None:
        csp = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])

    def test_inline_or_eval_script_sources_are_refused_but_hashes_pass(self) -> None:
        for source, fragment in (
            ("'unsafe-inline'", "runs code no file of this repository shipped"),
            ("'unsafe-eval'", "runs code no file of this repository shipped"),
            ("'strict-dynamic'", "a keyword this gate does not admit"),
        ):
            with self.subTest(source=source):
                csp = f"default-src 'self'; script-src 'self' {source}; frame-ancestors 'none'"
                self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp), {}), fragment)
        # Inline style is not script: the gate leaves it to the CSP tests that own it.
        csp = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])
        csp = "default-src 'self'; script-src 'self' 'sha256-abc='; frame-ancestors 'none'"
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])

    def test_framing_must_be_denied_somewhere(self) -> None:
        csp = "default-src 'self'"
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp, X_Frame_Options=None), {}), "framing")
        self.assertEqual(gate.judge(manifest(), document(Content_Security_Policy=csp), {}).refusals, [])
        wide = "default-src 'self'; frame-ancestors https://other.example"
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=wide), {}), "frame-ancestors admits")

    def test_hsts_must_last_a_year(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(Strict_Transport_Security="max-age=86400"), {}), "Strict-Transport-Security")
        self.assertRefused(gate.judge(manifest(), document(Strict_Transport_Security=None), {}), "Strict-Transport-Security")

    def test_nosniff_and_referrer_policy_are_required(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(X_Content_Type_Options=None), {}), "nosniff")
        self.assertRefused(gate.judge(manifest(), document(Referrer_Policy="unsafe-url"), {}), "Referrer-Policy")
        self.assertRefused(gate.judge(manifest(), document(Referrer_Policy=None), {}), "Referrer-Policy")

    def test_a_cookie_on_the_document_is_refused(self) -> None:
        self.assertRefused(gate.judge(manifest(), document(Set_Cookie="tracker=1; Path=/"), {}), "'tracker'")

    def test_an_undeclared_reporting_endpoint_is_refused_and_a_vanished_one_is_stale(self) -> None:
        other = json.dumps({"group": "x", "endpoints": [{"url": "https://collector.example/r"}]})
        self.assertRefused(gate.judge(manifest(), document(Report_To=other), {}), "undeclared origin https://collector.example")
        self.assertRefused(gate.judge(manifest(), document(Report_To=other), {}), f"reporting endpoint {REPORTS}, which no longer occurs")
        endpoints = 'default="https://collector.example/r"'
        self.assertRefused(gate.judge(manifest(), document(Reporting_Endpoints=endpoints), {}), "https://collector.example")
        csp = "default-src 'self'; frame-ancestors 'none'; report-uri https://collector.example/csp"
        self.assertRefused(gate.judge(manifest(), document(Content_Security_Policy=csp), {}), "https://collector.example")

    def test_an_undeclared_inline_script_is_refused_and_a_vanished_one_is_stale(self) -> None:
        html = HTML.replace(MARKER, "/something-else/")
        verdict = gate.judge(manifest(), document(html=html), {})
        self.assertRefused(verdict, "inline script this repository did not build")
        self.assertRefused(verdict, f"marked {MARKER!r} that no longer occurs")

    def test_a_remote_script_stylesheet_or_embed_in_the_html_is_refused(self) -> None:
        for snippet in (
            '<script src="https://cdn.example/x.js"></script>',
            '<link rel="stylesheet" href="https://fonts.example/css">',
            '<link rel="preconnect" href="https://fonts.example">',
            '<img src="https://pixel.example/p.gif" alt="">',
            '<iframe src="https://widget.example/"></iframe>',
            '<img srcset="/a.png 1x, https://pixel.example/b.png 2x" alt="">',
        ):
            with self.subTest(snippet=snippet):
                html = HTML.replace("</body>", snippet + "</body>")
                self.assertRefused(gate.judge(manifest(), document(html=html), {}), "loads")

    def test_a_published_legal_page_must_answer_html(self) -> None:
        published = manifest()
        published["legalPages"] = [{"id": "privacy", "status": "published", "path": "/privacy"}]
        ok = gate.Fetched(SITE + "privacy", 200, [("Content-Type", "text/html")], b"<p>notice</p>")
        self.assertEqual(gate.judge(published, document(), {"/privacy": ok}).refusals, [])
        missing = gate.Fetched(SITE + "privacy", 404, [("Content-Type", "text/plain")], b"")
        self.assertRefused(gate.judge(published, document(), {"/privacy": missing}), "answered 404")
        wrong = gate.Fetched(SITE + "privacy", 200, [("Content-Type", "application/json")], b"{}")
        self.assertRefused(gate.judge(published, document(), {"/privacy": wrong}), "not served as text/html")


class ValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.repo = Path(self.scratch.name)
        (self.repo / "evidence.go").write_text("package x\n")
        self.source = self.repo / "frontend" / "src"
        self.source.mkdir(parents=True)
        (self.source / "theme.ts").write_text("document.cookie = 'theme=' + id;\nstore.setItem(\"width\", v);\n")

    def refusals(self, value: object) -> list[str]:
        return gate.validate(value, source_root=self.source, repo_root=self.repo)

    def test_the_baseline_validates(self) -> None:
        self.assertEqual(self.refusals(manifest()), [])

    def test_the_schema_is_closed(self) -> None:
        extra = manifest()
        extra["thirdparties"] = []
        self.assertTrue(any("unknown key 'thirdparties'" in r for r in self.refusals(extra)))
        missing = manifest()
        del missing["legalPages"]
        self.assertTrue(any("'legalPages'" in r for r in self.refusals(missing)))
        nested = manifest()
        nested["storage"][0]["expires"] = "1y"
        self.assertTrue(any("unknown key 'expires'" in r for r in self.refusals(nested)))
        self.assertEqual(self.refusals([]), ["compliance.json must be one JSON object"])

    def test_every_field_needs_words(self) -> None:
        blank = manifest()
        blank["storage"][0]["purpose"] = " "
        self.assertTrue(any("storage[0].purpose" in r for r in self.refusals(blank)))

    def test_storage_must_be_written_by_the_visitor_and_still_written_somewhere(self) -> None:
        on_load = manifest()
        on_load["storage"][0]["writtenWhen"] = "on-load"
        self.assertTrue(any("needs consent" in r for r in self.refusals(on_load)))
        stale = manifest()
        stale["storage"][1]["name"] = "renamed"
        self.assertTrue(any("'renamed', which no file" in r for r in self.refusals(stale)))
        (self.source / "theme.ts").write_text("document.cookie = 'theme=' + id;\n")
        self.assertTrue(any("'width', which no file" in r for r in self.refusals(manifest())))

    def test_collection_evidence_must_exist(self) -> None:
        (self.repo / "evidence.go").unlink()
        self.assertTrue(any("evidence 'evidence.go' no longer exists" in r for r in self.refusals(manifest())))

    def test_third_parties_need_a_bare_origin_and_no_consent_requirement(self) -> None:
        bad = manifest()
        bad["thirdParties"] = [{"origin": "https://cdn.example/path", "purpose": "p", "consent": "required", "reason": "r"}]
        refusals = self.refusals(bad)
        self.assertTrue(any("bare https origin" in r for r in refusals))
        self.assertTrue(any("consent mechanism" in r for r in refusals))

    def test_legal_pages_are_published_with_a_path_or_pending_with_a_decision(self) -> None:
        for page, fragment in (
            ({"id": "privacy", "status": "published"}, "needs the absolute path"),
            ({"id": "privacy", "status": "pending"}, "needs the issue URL"),
            ({"id": "privacy", "status": "pending", "decision": "soon"}, "needs the issue URL"),
            ({"id": "privacy", "status": "drafted", "path": "/p"}, "status must be one of"),
        ):
            with self.subTest(page=page):
                value = manifest()
                value["legalPages"] = [page]
                self.assertTrue(any(fragment in r for r in self.refusals(value)), self.refusals(value))
        twice = manifest()
        twice["legalPages"] = twice["legalPages"] * 2
        self.assertTrue(any("declared twice" in r for r in self.refusals(twice)))

    def test_edge_observations_name_what_they_are_and_where_the_decision_lives(self) -> None:
        for change, fragment in (
            ({"kind": "cookie"}, "kind must be one of"),
            ({"issue": "later"}, "issue URL that holds the decision"),
        ):
            with self.subTest(change=change):
                value = manifest()
                value["edgeObservations"][0].update(change)
                self.assertTrue(any(fragment in r for r in self.refusals(value)))
        no_marker = manifest()
        del no_marker["edgeObservations"][0]["marker"]
        self.assertTrue(any("needs the marker" in r for r in self.refusals(no_marker)))
        no_origin = manifest()
        no_origin["edgeObservations"][1]["origin"] = "reports.example"
        self.assertTrue(any("bare https origin the reports go to" in r for r in self.refusals(no_origin)))

    def test_the_live_url_must_be_https(self) -> None:
        value = manifest()
        value["liveUrl"] = "http://site.example/"
        self.assertTrue(any("liveUrl" in r for r in self.refusals(value)))


class ShippedManifestTests(unittest.TestCase):
    def test_the_repository_manifest_validates(self) -> None:
        manifest_value = json.loads(gate.MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(gate.validate(manifest_value), [])

    def test_check_mode_reports_its_decision(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(gate.main(["check"]), 0)
        self.assertIn("SUMMARY mode=check decision=pass refusals=0", output.getvalue())

    def test_check_mode_fails_on_an_unreadable_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            broken = Path(scratch) / "compliance.json"
            broken.write_text("{")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.main(["check", "--manifest", str(broken)]), 1)
        self.assertIn("decision=fail", output.getvalue())


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - the stdlib names it
        status = 404 if self.path == "/missing" else 200
        body = HTML.encode()
        self.send_response(status)
        for key, value in headers():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_: object) -> None:
        return


class LiveModeTests(unittest.TestCase):
    """The fetch layer and `live` end to end, against a loopback server."""

    def setUp(self) -> None:
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.addCleanup(self.server.server_close)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def test_fetch_keeps_an_error_answer_instead_of_raising(self) -> None:
        answer = gate.fetch(self.base + "/missing")
        self.assertEqual(answer.status, 404)
        self.assertEqual(answer.first("x-frame-options"), "DENY")

    def test_live_mode_passes_the_compliant_site_and_fails_a_regression(self) -> None:
        base = self.base

        def fetcher(url: str) -> gate.Fetched:
            answer = gate.fetch(base + "/" + url.split("/", 3)[3])
            return gate.Fetched(url, answer.status, answer.headers, answer.body)

        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "compliance.json"
            value = json.loads(gate.MANIFEST.read_text(encoding="utf-8"))
            value["liveUrl"] = SITE
            value["edgeObservations"] = manifest()["edgeObservations"]
            path.write_text(json.dumps(value))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.run_live(path, fetcher=fetcher), 0, output.getvalue())
            self.assertIn("START mode=live", output.getvalue())
            self.assertIn("decision=pass", output.getvalue())

            value["edgeObservations"] = []
            path.write_text(json.dumps(value))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(gate.run_live(path, fetcher=fetcher), 1)
            self.assertIn("decision=fail refusals=2", output.getvalue())

    def test_live_mode_fails_closed_when_the_site_cannot_be_read(self) -> None:
        def unreachable(url: str) -> gate.Fetched:
            raise OSError("connection refused")

        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(gate.run_live(gate.MANIFEST, fetcher=unreachable), 1)
        self.assertIn("could not be read", output.getvalue())


if __name__ == "__main__":
    unittest.main()
