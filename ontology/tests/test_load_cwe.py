from __future__ import annotations

import contextlib
import hashlib
import io
import json
import stat
import sys
import unittest
import zipfile
from pathlib import Path

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
    def __init__(self, chunks: list[bytes], *, content_length: str | None = None):
        self._chunks = chunks
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        self.url = load_cwe.CWE_ZIP_URL

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

    def get(self, *_args, **_kwargs):
        return self.response


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

    def test_download_rejects_streams_above_the_bound(self):
        response = FakeResponse([b"1234", b"5678"])
        with self.assertRaisesRegex(load_cwe.CatalogError, "compressed-size"):
            load_cwe.download_archive(
                session=FakeSession(response),
                max_bytes=7,
            )

    def test_download_rejects_non_https_urls(self):
        with self.assertRaisesRegex(load_cwe.CatalogError, "must use HTTPS"):
            load_cwe.download_archive(
                "http://cwe.mitre.org/catalog.zip",
                session=FakeSession(FakeResponse([])),
            )


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
        with self.assertRaisesRegex(load_cwe.CatalogError, "applies to ZIP"):
            load_cwe.run(
                [
                    "--xml",
                    str(FIXTURE),
                    "--dry-run",
                    "--sha256",
                    "0" * 64,
                ]
            )


if __name__ == "__main__":
    unittest.main()
