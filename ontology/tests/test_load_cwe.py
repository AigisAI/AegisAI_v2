from __future__ import annotations

import contextlib
import hashlib
import io
import json
import stat
import sys
import types
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest import mock

ONTOLOGY_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ONTOLOGY_DIR))

import load_cwe  # noqa: E402


FIXTURE = Path(__file__).parent / "fixtures" / "cwe-mini.xml"
ARCHIVE_DIGEST = "a" * 64


def build_archive(content: bytes, name: str = "cwec_test.xml") -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return buffer.getvalue()


class FakeResponse:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        content_length: str | None = None,
        history_urls: tuple[str, ...] = (),
        url: str = load_cwe.CWE_ZIP_URL,
    ):
        self._chunks = chunks
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.history = [types.SimpleNamespace(url=value) for value in history_urls]
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def raise_for_status(self):
        return None

    def iter_content(self, *, chunk_size: int):
        self.chunk_size = chunk_size
        yield from self._chunks


class FakeSession:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.kwargs: dict = {}

    def get(self, *_args, **kwargs):
        self.kwargs = kwargs
        return self.response


class FakeResult:
    def __init__(self, count: int = 0):
        self.count = count

    def consume(self):
        return None

    def single(self, *, strict: bool):
        assert strict
        return {"count": self.count}


class FakeTransaction:
    def __init__(self):
        self.queries: list[tuple[str, dict]] = []

    def run(self, query: str, **parameters):
        self.queries.append((" ".join(query.split()), parameters))
        return FakeResult()


class FakeNeo4jSession:
    def __init__(self, summary: dict[str, int | str]):
        self.summary = summary
        self.transaction = FakeTransaction()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute_write(self, callback):
        callback(self.transaction)

    def run(self, query: str, **_parameters):
        normalized = " ".join(query.split())
        if "RETURN count" not in normalized:
            return FakeResult()
        if "managedBy" in normalized and "m:Mitigation" in normalized:
            return FakeResult(int(self.summary["mitigationCount"]))
        if "managedBy" in normalized and "c:CWE" in normalized:
            return FakeResult(int(self.summary["cweCount"]))
        if "CHILD_OF" in normalized:
            return FakeResult(int(self.summary["childOfCount"]))
        if "PEER_OF" in normalized:
            return FakeResult(int(self.summary["peerOfCount"]))
        if "MITIGATED_BY" in normalized:
            return FakeResult(int(self.summary["mitigationCount"]))
        return FakeResult(int(self.summary["cweCount"]))


class FakeNeo4jDriver:
    def __init__(self, session: FakeNeo4jSession):
        self._session = session
        self.closed = False

    def verify_connectivity(self):
        return None

    def session(self, *, database: str):
        assert database == "neo4j"
        return self._session

    def close(self):
        self.closed = True


def execute_with_fake_neo4j(catalog: load_cwe.ParsedCatalog):
    session = FakeNeo4jSession(catalog.summary())
    driver = FakeNeo4jDriver(session)
    neo4j_module = types.ModuleType("neo4j")
    neo4j_module.GraphDatabase = types.SimpleNamespace(
        driver=lambda *_args, **_kwargs: driver
    )
    with mock.patch.dict(sys.modules, {"neo4j": neo4j_module}):
        result = load_cwe._load_catalog(
            catalog,
            uri="bolt://localhost:7687",
            user="neo4j",
            password="test-only-password",
            database="neo4j",
        )
    return result, session.transaction.queries, driver


class CatalogParsingTests(unittest.TestCase):
    def test_parses_cwes_relationships_and_stable_mitigations(self):
        xml_bytes = FIXTURE.read_bytes()
        first = load_cwe.parse_catalog(xml_bytes, source_sha256=ARCHIVE_DIGEST)
        second = load_cwe.parse_catalog(xml_bytes, source_sha256=ARCHIVE_DIGEST)

        self.assertEqual(
            first.summary(),
            {
                "catalogVersion": "4.17",
                "catalogDate": "2026-01-01",
                "sourceSha256": ARCHIVE_DIGEST,
                "cweCount": 2,
                "childOfCount": 1,
                "peerOfCount": 1,
                "mitigationCount": 2,
            },
        )
        self.assertEqual(first, second)
        self.assertIn(
            {"src": "CWE-89", "dst": "CWE-943", "kind": "CHILD_OF"},
            first.relations,
        )
        self.assertEqual(first.cwes[0]["description"].count("\n"), 0)
        self.assertTrue(
            all(row["id"].startswith("CWE-89-M-") for row in first.mitigations)
        )

    def test_filters_nodes_and_relationships_to_the_selected_set(self):
        catalog = load_cwe.parse_catalog(
            FIXTURE.read_bytes(),
            source_sha256=ARCHIVE_DIGEST,
            selected_ids=["89"],
        )

        self.assertEqual([row["id"] for row in catalog.cwes], ["CWE-89"])
        self.assertEqual(catalog.relations, ())
        self.assertEqual(len(catalog.mitigations), 2)

    def test_rejects_doctype_and_entity_declarations(self):
        malicious = b"""<?xml version='1.0'?>
<!DOCTYPE Weakness_Catalog [<!ENTITY leak SYSTEM 'file:///etc/passwd'>]>
<Weakness_Catalog xmlns='http://cwe.mitre.org/cwe-7' Version='1' Date='2026-01-01'>
<Weaknesses><Weakness ID='1' Name='x'><Description>&leak;</Description></Weakness></Weaknesses>
</Weakness_Catalog>"""

        with self.assertRaisesRegex(load_cwe.CatalogError, "DTD and entity"):
            load_cwe.parse_catalog(malicious, source_sha256=ARCHIVE_DIGEST)

    def test_rejects_non_utf8_dtd_before_parsing(self):
        malicious = """<?xml version='1.0' encoding='UTF-16'?>
<!DOCTYPE Weakness_Catalog>
<Weakness_Catalog xmlns='http://cwe.mitre.org/cwe-7' Version='1.0' Date='2026-01-01'>
<Weaknesses><Weakness ID='1' Name='x'/></Weaknesses>
</Weakness_Catalog>""".encode("utf-16")

        with self.assertRaisesRegex(load_cwe.CatalogError, "must use UTF-8"):
            load_cwe.parse_catalog(malicious, source_sha256=ARCHIVE_DIGEST)

    def test_rejects_duplicate_weakness_ids(self):
        xml_bytes = FIXTURE.read_bytes().replace(
            b'<Weakness ID="943"', b'<Weakness ID="89"', 1
        )

        with self.assertRaisesRegex(load_cwe.CatalogError, "duplicate weakness"):
            load_cwe.parse_catalog(xml_bytes, source_sha256=ARCHIVE_DIGEST)

    def test_rejects_an_explicitly_empty_selection(self):
        with self.assertRaisesRegex(load_cwe.CatalogError, "at least one CWE"):
            load_cwe.parse_catalog(
                FIXTURE.read_bytes(),
                source_sha256=ARCHIVE_DIGEST,
                selected_ids=[],
            )


class ArchiveBoundaryTests(unittest.TestCase):
    def test_extracts_one_flat_xml_and_verifies_sha256(self):
        archive = build_archive(FIXTURE.read_bytes())
        digest = hashlib.sha256(archive).hexdigest()

        xml_bytes, observed_digest = load_cwe.extract_catalog_xml(
            archive, expected_sha256=digest
        )

        self.assertEqual(xml_bytes, FIXTURE.read_bytes())
        self.assertEqual(observed_digest, digest)

    def test_rejects_digest_mismatch_and_nested_entries(self):
        archive = build_archive(FIXTURE.read_bytes())
        with self.assertRaisesRegex(load_cwe.CatalogError, "SHA-256 mismatch"):
            load_cwe.extract_catalog_xml(archive, expected_sha256="0" * 64)

        nested = build_archive(FIXTURE.read_bytes(), "nested/cwe.xml")
        with self.assertRaisesRegex(load_cwe.CatalogError, "unsafe"):
            load_cwe.extract_catalog_xml(nested)

    def test_rejects_a_zip_symlink_entry(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            entry = zipfile.ZipInfo("cwe.xml")
            entry.create_system = 3
            entry.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(entry, b"target.xml")

        with self.assertRaisesRegex(load_cwe.CatalogError, "unsafe"):
            load_cwe.extract_catalog_xml(buffer.getvalue())

    def test_rejects_corrupt_deflate_streams_without_a_traceback(self):
        with mock.patch.object(
            load_cwe.zipfile,
            "ZipFile",
            side_effect=zlib.error("corrupt deflate stream"),
        ):
            with self.assertRaisesRegex(load_cwe.CatalogError, "valid ZIP"):
                load_cwe.extract_catalog_xml(b"not-a-valid-archive")

    def test_rejects_excessive_compression_ratios(self):
        archive = build_archive(b"A" * 100_000)

        with self.assertRaisesRegex(load_cwe.CatalogError, "compression-ratio"):
            load_cwe.extract_catalog_xml(archive)

    def test_download_rejects_streams_above_the_bound(self):
        response = FakeResponse([b"1234", b"5678"])
        session = FakeSession(response)
        with self.assertRaisesRegex(load_cwe.CatalogError, "compressed-size"):
            load_cwe.download_archive(
                session=session,
                max_bytes=7,
            )
        self.assertEqual(session.kwargs["timeout"], (10, 120))
        self.assertIs(session.kwargs["stream"], True)
        self.assertIs(session.kwargs["allow_redirects"], True)

    def test_download_rejects_invalid_or_oversized_content_length(self):
        for value, message in (("not-a-number", "invalid"), ("8", "compressed-size")):
            with self.subTest(content_length=value):
                response = FakeResponse([], content_length=value)
                with self.assertRaisesRegex(load_cwe.CatalogError, message):
                    load_cwe.download_archive(
                        session=FakeSession(response),
                        max_bytes=7,
                    )

    def test_download_rejects_plain_http_in_a_redirect_chain(self):
        response = FakeResponse([], history_urls=("http://mirror.example/cwe.zip",))
        with self.assertRaisesRegex(load_cwe.CatalogError, "remain on HTTPS"):
            load_cwe.download_archive(session=FakeSession(response))

    def test_download_rejects_non_https_urls(self):
        with self.assertRaisesRegex(load_cwe.CatalogError, "must use HTTPS"):
            load_cwe.download_archive(
                "http://cwe.mitre.org/catalog.zip",
                session=FakeSession(FakeResponse([])),
            )


class Neo4jWriteTests(unittest.TestCase):
    def test_missing_password_fails_before_loading_the_driver(self):
        catalog = load_cwe.parse_catalog(
            FIXTURE.read_bytes(), source_sha256=ARCHIVE_DIGEST
        )

        with self.assertRaisesRegex(load_cwe.CatalogError, "NEO4J_PASSWORD"):
            load_cwe.load_catalog(
                catalog,
                uri="bolt://localhost:7687",
                user="neo4j",
                password="",
                database="neo4j",
            )

    def test_full_import_reconciles_only_importer_owned_snapshot(self):
        catalog = load_cwe.parse_catalog(
            FIXTURE.read_bytes(), source_sha256=ARCHIVE_DIGEST
        )

        persisted, queries, driver = execute_with_fake_neo4j(catalog)
        query_text = "\n".join(query for query, _parameters in queries)

        self.assertTrue(driver.closed)
        self.assertEqual(persisted["managedCweCount"], 2)
        self.assertEqual(persisted["managedMitigationCount"], 2)
        self.assertIn("c.managedBy = $managed_by", query_text)
        self.assertIn("DETACH DELETE c", query_text)
        self.assertIn("CHILD_OF|PEER_OF|MITIGATED_BY", query_text)
        self.assertIn("m.cwe = row.cwe", query_text)
        self.assertIn("m.managedBy = $managed_by", query_text)
        self.assertIn("NOT EXISTS", query_text)

    def test_subset_import_preserves_existing_hierarchy_edges(self):
        catalog = load_cwe.parse_catalog(
            FIXTURE.read_bytes(),
            source_sha256=ARCHIVE_DIGEST,
            selected_ids=["CWE-89"],
        )

        persisted, queries, _driver = execute_with_fake_neo4j(catalog)
        deletion_queries = [
            query for query, _parameters in queries if "DELETE r" in query
        ]

        self.assertNotIn("managedCweCount", persisted)
        self.assertEqual(len(deletion_queries), 1)
        self.assertIn("[r:MITIGATED_BY]", deletion_queries[0])
        self.assertNotIn("CHILD_OF|PEER_OF", deletion_queries[0])
        self.assertFalse(any("DETACH DELETE c" in query for query, _ in queries))

    def test_driver_failures_are_mapped_to_catalog_error(self):
        class FakeDriverError(Exception):
            pass

        class FakeNeo4jError(Exception):
            pass

        neo4j_module = types.ModuleType("neo4j")
        neo4j_module.GraphDatabase = types.SimpleNamespace(
            driver=mock.Mock(side_effect=FakeDriverError("secret connection detail"))
        )
        exceptions_module = types.ModuleType("neo4j.exceptions")
        exceptions_module.DriverError = FakeDriverError
        exceptions_module.Neo4jError = FakeNeo4jError
        catalog = load_cwe.parse_catalog(
            FIXTURE.read_bytes(), source_sha256=ARCHIVE_DIGEST
        )

        with mock.patch.dict(
            sys.modules,
            {"neo4j": neo4j_module, "neo4j.exceptions": exceptions_module},
        ):
            with self.assertRaisesRegex(load_cwe.CatalogError, "Neo4j import failed") as raised:
                load_cwe.load_catalog(
                    catalog,
                    uri="bolt://localhost:7687",
                    user="neo4j",
                    password="test-only-password",
                    database="neo4j",
                )

        self.assertNotIn("secret connection detail", str(raised.exception))


class CommandTests(unittest.TestCase):
    def test_dry_run_validates_and_emits_a_bounded_summary(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = load_cwe.run(
                [
                    "--xml",
                    str(FIXTURE),
                    "--dry-run",
                    "--expect-cwe-count",
                    "2",
                    "--expect-child-of-count",
                    "1",
                    "--expect-mitigation-count",
                    "2",
                ]
            )

        self.assertEqual(result, 0)
        summary = json.loads(output.getvalue())
        self.assertTrue(summary["dryRun"])
        self.assertEqual(summary["source"]["cweCount"], 2)
        self.assertNotIn("password", output.getvalue().lower())

    def test_xml_input_rejects_zip_digest_option(self):
        error_output = io.StringIO()
        with (
            mock.patch.object(load_cwe, "_read_bounded_file") as bounded_read,
            contextlib.redirect_stderr(error_output),
            self.assertRaises(SystemExit) as raised,
        ):
            load_cwe.run(
                [
                    "--xml",
                    str(FIXTURE),
                    "--dry-run",
                    "--sha256",
                    "0" * 64,
                ]
            )

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("applies to ZIP", error_output.getvalue())
        bounded_read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
