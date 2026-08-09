from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence, TypedDict
from urllib.parse import urlparse

from lxml import etree

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_XML_NAMESPACE = "http://cwe.mitre.org/cwe-7"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_XML_BYTES = 128 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_TEXT_BYTES = 16 * 1024
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
CWE_ID_PATTERN = re.compile(r"^(?:CWE-)?([1-9][0-9]{0,6})$")
CATALOG_VERSION_PATTERN = re.compile(r"^[1-9][0-9]*(?:\.[0-9]+){1,2}$")
CATALOG_DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
RELATIONSHIP_TYPES = {"ChildOf": "CHILD_OF", "PeerOf": "PEER_OF"}
IMPORT_OWNER = "aegisai-cwe-importer-v1"
XML_DECLARATION_PATTERN = re.compile(r"<!\s*(?:DOCTYPE|ENTITY)\b")


class CatalogError(ValueError):
    """Raised when the source archive or CWE catalog fails closed validation."""


class CweRow(TypedDict):
    id: str
    name: str
    abstraction: str
    status: str
    likelihood: str
    description: str
    catalogVersion: str
    catalogDate: str
    sourceSha256: str


class RelationRow(TypedDict):
    src: str
    dst: str
    kind: str


class MitigationRow(TypedDict):
    id: str
    cwe: str
    phases: list[str]
    description: str
    catalogVersion: str
    sourceSha256: str


@dataclass(frozen=True)
class ParsedCatalog:
    version: str
    date: str
    source_sha256: str
    cwes: tuple[CweRow, ...]
    relations: tuple[RelationRow, ...]
    mitigations: tuple[MitigationRow, ...]
    is_full_catalog: bool

    @property
    def child_of_count(self) -> int:
        return sum(row["kind"] == "CHILD_OF" for row in self.relations)

    @property
    def peer_of_count(self) -> int:
        return sum(row["kind"] == "PEER_OF" for row in self.relations)

    def summary(self) -> dict[str, Any]:
        return {
            "catalogVersion": self.version,
            "catalogDate": self.date,
            "sourceSha256": self.source_sha256,
            "cweCount": len(self.cwes),
            "childOfCount": self.child_of_count,
            "peerOfCount": self.peer_of_count,
            "mitigationCount": len(self.mitigations),
        }


def _normalize_cwe_id(value: str) -> str:
    match = CWE_ID_PATTERN.fullmatch(value.strip())
    if match is None:
        raise CatalogError(f"invalid CWE identifier: {value!r}")
    return f"CWE-{match.group(1)}"


def _bounded_text(element: etree._Element | None, limit: int = MAX_TEXT_BYTES) -> str:
    if element is None:
        return ""
    value = " ".join(" ".join(element.itertext()).split())
    if len(value.encode("utf-8")) > limit:
        raise CatalogError("catalog text exceeds the configured UTF-8 byte limit")
    return value


def _bounded_attribute(element: etree._Element, name: str, limit: int = 512) -> str:
    value = " ".join((element.get(name) or "").split())
    if len(value.encode("utf-8")) > limit:
        raise CatalogError(f"catalog attribute {name!r} exceeds the byte limit")
    return value


def _read_bounded_file(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise CatalogError(f"{path} exceeds the {limit}-byte input limit")
    with path.open("rb") as source:
        content = source.read(limit + 1)
    if len(content) > limit:
        raise CatalogError(f"{path} exceeds the {limit}-byte input limit")
    return content


def _validate_expected_sha256(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if SHA256_PATTERN.fullmatch(normalized) is None:
        raise CatalogError("expected SHA-256 must be 64 lowercase hexadecimal characters")
    return normalized


def download_archive(
    url: str = CWE_ZIP_URL,
    *,
    session: Any | None = None,
    max_bytes: int = MAX_ARCHIVE_BYTES,
) -> bytes:
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.hostname:
        raise CatalogError("CWE archive URL must use HTTPS")

    owns_session = session is None
    if session is None:
        import requests

        session = requests.Session()

    try:
        with session.get(
            url,
            headers={"User-Agent": "AegisAI-CWE-Importer/1.0"},
            stream=True,
            timeout=(10, 120),
            allow_redirects=True,
        ) as response:
            response.raise_for_status()
            redirect_chain = [*getattr(response, "history", ()), response]
            for redirect_response in redirect_chain:
                redirect_url = urlparse(redirect_response.url)
                if redirect_url.scheme != "https" or not redirect_url.hostname:
                    raise CatalogError("CWE archive redirect must remain on HTTPS")

            content_length = response.headers.get("Content-Length")
            if content_length is not None:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise CatalogError("invalid CWE archive Content-Length") from exc
                if declared_length < 0 or declared_length > max_bytes:
                    raise CatalogError("CWE archive exceeds the compressed-size limit")

            chunks: list[bytes] = []
            observed = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                observed += len(chunk)
                if observed > max_bytes:
                    raise CatalogError("CWE archive exceeds the compressed-size limit")
                chunks.append(chunk)
            return b"".join(chunks)
    finally:
        if owns_session:
            session.close()


def extract_catalog_xml(
    archive_bytes: bytes,
    *,
    expected_sha256: str | None = None,
    max_xml_bytes: int = MAX_XML_BYTES,
) -> tuple[bytes, str]:
    if len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise CatalogError("CWE archive exceeds the compressed-size limit")

    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    expected = _validate_expected_sha256(expected_sha256)
    if expected is not None and archive_sha256 != expected:
        raise CatalogError("CWE archive SHA-256 mismatch")

    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            candidates = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".xml")
            ]
            if len(candidates) != 1:
                raise CatalogError("CWE archive must contain exactly one XML file")

            info = candidates[0]
            archive_path = PurePosixPath(info.filename)
            entry_mode = info.external_attr >> 16
            if (
                archive_path.name != info.filename
                or info.flag_bits & 0x1
                or stat.S_ISLNK(entry_mode)
            ):
                raise CatalogError("CWE archive contains an unsafe or encrypted XML entry")
            if info.file_size <= 0 or info.file_size > max_xml_bytes:
                raise CatalogError("CWE XML exceeds the expanded-size limit")
            if info.compress_size <= 0:
                raise CatalogError("CWE XML has invalid compressed-size metadata")
            if info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise CatalogError("CWE XML exceeds the compression-ratio limit")

            with archive.open(info, "r") as source:
                xml_bytes = source.read(max_xml_bytes + 1)
            if len(xml_bytes) != info.file_size or len(xml_bytes) > max_xml_bytes:
                raise CatalogError("CWE XML size does not match bounded archive metadata")
            return xml_bytes, archive_sha256
    except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
        raise CatalogError("CWE source is not a valid ZIP archive") from exc


def parse_catalog(
    xml_bytes: bytes,
    *,
    source_sha256: str,
    selected_ids: Iterable[str] | None = None,
) -> ParsedCatalog:
    if len(xml_bytes) <= 0 or len(xml_bytes) > MAX_XML_BYTES:
        raise CatalogError("CWE XML size is outside the allowed range")
    try:
        decoded_xml = xml_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CatalogError("CWE XML must use UTF-8 encoding") from exc
    if XML_DECLARATION_PATTERN.search(decoded_xml):
        raise CatalogError("DTD and entity declarations are not allowed")
    if SHA256_PATTERN.fullmatch(source_sha256) is None:
        raise CatalogError("source SHA-256 is invalid")

    parser = etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        huge_tree=False,
        recover=False,
        remove_comments=True,
    )
    try:
        root = etree.fromstring(xml_bytes, parser=parser)
    except (etree.XMLSyntaxError, ValueError) as exc:
        raise CatalogError("CWE XML is malformed") from exc
    if root.getroottree().docinfo.doctype:
        raise CatalogError("DTD and entity declarations are not allowed")

    root_name = etree.QName(root)
    namespace = root_name.namespace or ""
    if root_name.localname != "Weakness_Catalog" or namespace != CWE_XML_NAMESPACE:
        raise CatalogError("unexpected CWE catalog root or namespace")

    ns = {"cwe": namespace}
    version = _bounded_attribute(root, "Version", 64)
    catalog_date = _bounded_attribute(root, "Date", 64)
    if CATALOG_VERSION_PATTERN.fullmatch(version) is None:
        raise CatalogError("CWE catalog version is missing or invalid")
    if CATALOG_DATE_PATTERN.fullmatch(catalog_date) is None:
        raise CatalogError("CWE catalog date is missing or invalid")

    weaknesses = root.findall("cwe:Weaknesses/cwe:Weakness", ns)
    if not weaknesses:
        raise CatalogError("CWE catalog contains no weaknesses")

    by_id: dict[str, etree._Element] = {}
    for weakness in weaknesses:
        cwe_id = _normalize_cwe_id(weakness.get("ID") or "")
        if cwe_id in by_id:
            raise CatalogError(f"duplicate weakness identifier: {cwe_id}")
        by_id[cwe_id] = weakness

    if selected_ids is None:
        selected = set(by_id)
    else:
        selected = {_normalize_cwe_id(value) for value in selected_ids}
        missing = sorted(selected.difference(by_id))
        if missing:
            raise CatalogError(f"selected CWE identifiers are missing: {', '.join(missing)}")
    if not selected:
        raise CatalogError("at least one CWE identifier must be selected")

    cwes: list[CweRow] = []
    relation_keys: set[tuple[str, str, str]] = set()
    mitigation_by_id: dict[str, MitigationRow] = {}

    for cwe_id in sorted(selected, key=lambda value: int(value[4:])):
        weakness = by_id[cwe_id]
        cwes.append(
            {
                "id": cwe_id,
                "name": _bounded_attribute(weakness, "Name"),
                "abstraction": _bounded_attribute(weakness, "Abstraction", 64),
                "status": _bounded_attribute(weakness, "Status", 64),
                "likelihood": _bounded_text(
                    weakness.find("cwe:Likelihood_Of_Exploit", ns), 128
                ),
                "description": _bounded_text(weakness.find("cwe:Description", ns)),
                "catalogVersion": version,
                "catalogDate": catalog_date,
                "sourceSha256": source_sha256,
            }
        )

        for related in weakness.findall(
            "cwe:Related_Weaknesses/cwe:Related_Weakness", ns
        ):
            relation_kind = RELATIONSHIP_TYPES.get(related.get("Nature") or "")
            target = related.get("CWE_ID")
            if relation_kind is None or target is None:
                continue
            target_id = _normalize_cwe_id(target)
            if target_id in selected:
                relation_keys.add((cwe_id, target_id, relation_kind))

        for mitigation in weakness.findall(
            "cwe:Potential_Mitigations/cwe:Mitigation", ns
        ):
            phase_values: set[str] = set()
            for phase in mitigation.findall("cwe:Phase", ns):
                value = _bounded_text(phase, 256)
                if value:
                    phase_values.add(value)
            phases = sorted(phase_values)
            description = _bounded_text(mitigation.find("cwe:Description", ns))
            if not phases and not description:
                continue
            identity = "\x00".join((cwe_id, "\x1f".join(phases), description))
            identity_digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
            mitigation_id = f"{cwe_id}-M-{identity_digest[:24]}"
            mitigation_by_id[mitigation_id] = {
                "id": mitigation_id,
                "cwe": cwe_id,
                "phases": phases,
                "description": description,
                "catalogVersion": version,
                "sourceSha256": source_sha256,
            }

    relations = tuple(
        {"src": src, "dst": dst, "kind": kind}
        for src, dst, kind in sorted(relation_keys)
    )
    mitigations = tuple(mitigation_by_id[key] for key in sorted(mitigation_by_id))
    return ParsedCatalog(
        version=version,
        date=catalog_date,
        source_sha256=source_sha256,
        cwes=tuple(cwes),
        relations=relations,
        mitigations=mitigations,
        is_full_catalog=selected_ids is None,
    )


def _consume(result: Any) -> None:
    result.consume()


def _load_catalog(
    catalog: ParsedCatalog,
    *,
    uri: str,
    user: str,
    password: str,
    database: str,
) -> dict[str, Any]:
    if not password:
        raise CatalogError("NEO4J_PASSWORD is required")

    from neo4j import GraphDatabase

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        driver.verify_connectivity()
        with driver.session(database=database) as session:
            _consume(
                session.run(
                    "CREATE CONSTRAINT cwe_id IF NOT EXISTS "
                    "FOR (c:CWE) REQUIRE c.id IS UNIQUE"
                )
            )
            _consume(
                session.run(
                    "CREATE CONSTRAINT mitigation_id IF NOT EXISTS "
                    "FOR (m:Mitigation) REQUIRE m.id IS UNIQUE"
                )
            )

            cwe_ids = [row["id"] for row in catalog.cwes]
            child_rows = [
                row for row in catalog.relations if row["kind"] == "CHILD_OF"
            ]
            peer_rows = [row for row in catalog.relations if row["kind"] == "PEER_OF"]

            def write_catalog(tx: Any) -> None:
                _consume(
                    tx.run(
                        """
                        UNWIND $rows AS row
                        MERGE (c:CWE {id: row.id})
                        SET c.name = row.name,
                            c.abstraction = row.abstraction,
                            c.status = row.status,
                            c.likelihood = row.likelihood,
                            c.description = row.description,
                            c.catalogVersion = row.catalogVersion,
                            c.catalogDate = row.catalogDate,
                            c.sourceSha256 = row.sourceSha256,
                            c.managedBy = $managed_by
                        """,
                        rows=list(catalog.cwes),
                        managed_by=IMPORT_OWNER,
                    )
                )
                if catalog.is_full_catalog:
                    _consume(
                        tx.run(
                            """
                            MATCH (c:CWE {managedBy: $managed_by})
                            WHERE NOT (c.id IN $ids)
                            DETACH DELETE c
                            """,
                            ids=cwe_ids,
                            managed_by=IMPORT_OWNER,
                        )
                    )
                    relationship_cleanup = """
                        MATCH (c:CWE)-[r:CHILD_OF|PEER_OF|MITIGATED_BY]->()
                        WHERE c.id IN $ids
                        DELETE r
                        """
                else:
                    relationship_cleanup = """
                        MATCH (c:CWE)-[r:MITIGATED_BY]->()
                        WHERE c.id IN $ids
                        DELETE r
                    """
                _consume(
                    tx.run(
                        relationship_cleanup,
                        ids=cwe_ids,
                    )
                )
                _consume(
                    tx.run(
                        """
                        UNWIND $rows AS row
                        MATCH (source:CWE {id: row.src}), (target:CWE {id: row.dst})
                        MERGE (source)-[:CHILD_OF]->(target)
                        """,
                        rows=child_rows,
                    )
                )
                _consume(
                    tx.run(
                        """
                        UNWIND $rows AS row
                        MATCH (source:CWE {id: row.src}), (target:CWE {id: row.dst})
                        MERGE (source)-[:PEER_OF]->(target)
                        """,
                        rows=peer_rows,
                    )
                )
                _consume(
                    tx.run(
                        """
                        UNWIND $rows AS row
                        MATCH (c:CWE {id: row.cwe})
                        MERGE (m:Mitigation {id: row.id})
                        SET m.cwe = row.cwe,
                            m.phases = row.phases,
                            m.description = row.description,
                            m.catalogVersion = row.catalogVersion,
                            m.sourceSha256 = row.sourceSha256,
                            m.managedBy = $managed_by
                        MERGE (c)-[:MITIGATED_BY]->(m)
                        """,
                        rows=list(catalog.mitigations),
                        managed_by=IMPORT_OWNER,
                    )
                )
                if catalog.is_full_catalog:
                    mitigation_cleanup = """
                        MATCH (m:Mitigation {managedBy: $managed_by})
                        WHERE NOT EXISTS {
                            MATCH (:CWE)-[:MITIGATED_BY]->(m)
                        }
                        DELETE m
                    """
                    mitigation_cleanup_parameters = {"managed_by": IMPORT_OWNER}
                else:
                    mitigation_cleanup = """
                        MATCH (m:Mitigation {managedBy: $managed_by})
                        WHERE m.cwe IN $ids AND NOT EXISTS {
                            MATCH (:CWE)-[:MITIGATED_BY]->(m)
                        }
                        DELETE m
                    """
                    mitigation_cleanup_parameters = {
                        "ids": cwe_ids,
                        "managed_by": IMPORT_OWNER,
                    }
                _consume(
                    tx.run(
                        mitigation_cleanup,
                        **mitigation_cleanup_parameters,
                    )
                )

            session.execute_write(write_catalog)

            persisted = {
                "cweCount": session.run(
                    "MATCH (c:CWE) WHERE c.id IN $ids RETURN count(c) AS count",
                    ids=cwe_ids,
                ).single(strict=True)["count"],
                "childOfCount": session.run(
                    """
                    MATCH (source:CWE)-[r:CHILD_OF]->(target:CWE)
                    WHERE source.id IN $ids AND target.id IN $ids
                    RETURN count(r) AS count
                    """,
                    ids=cwe_ids,
                ).single(strict=True)["count"],
                "peerOfCount": session.run(
                    """
                    MATCH (source:CWE)-[r:PEER_OF]->(target:CWE)
                    WHERE source.id IN $ids AND target.id IN $ids
                    RETURN count(r) AS count
                    """,
                    ids=cwe_ids,
                ).single(strict=True)["count"],
                "mitigationCount": session.run(
                    """
                    MATCH (source:CWE)-[r:MITIGATED_BY]->(:Mitigation)
                    WHERE source.id IN $ids
                    RETURN count(r) AS count
                    """,
                    ids=cwe_ids,
                ).single(strict=True)["count"],
            }
            if catalog.is_full_catalog:
                persisted["managedCweCount"] = session.run(
                    "MATCH (c:CWE {managedBy: $managed_by}) "
                    "RETURN count(c) AS count",
                    managed_by=IMPORT_OWNER,
                ).single(strict=True)["count"]
                persisted["managedMitigationCount"] = session.run(
                    "MATCH (m:Mitigation {managedBy: $managed_by}) "
                    "RETURN count(m) AS count",
                    managed_by=IMPORT_OWNER,
                ).single(strict=True)["count"]
    finally:
        driver.close()

    expected = catalog.summary()
    expected_counts = {
        key: expected[key]
        for key in ("cweCount", "childOfCount", "peerOfCount", "mitigationCount")
    }
    if catalog.is_full_catalog:
        expected_counts["managedCweCount"] = expected["cweCount"]
        expected_counts["managedMitigationCount"] = expected["mitigationCount"]
    for key, expected_count in expected_counts.items():
        if persisted[key] != expected_count:
            raise CatalogError(
                f"Neo4j verification failed for {key}: "
                f"expected {expected_count}, observed {persisted[key]}"
            )
    return persisted


def load_catalog(
    catalog: ParsedCatalog,
    *,
    uri: str,
    user: str,
    password: str,
    database: str,
) -> dict[str, Any]:
    if not password:
        raise CatalogError("NEO4J_PASSWORD is required")

    from neo4j.exceptions import DriverError, Neo4jError

    try:
        return _load_catalog(
            catalog,
            uri=uri,
            user=user,
            password=password,
            database=database,
        )
    except (DriverError, Neo4jError) as exc:
        raise CatalogError(f"Neo4j import failed ({type(exc).__name__})") from exc


def _positive_count(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("count must be non-negative")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download, validate, and idempotently import MITRE CWE into Neo4j."
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--archive", type=Path, help="Path to a CWE ZIP archive")
    source.add_argument("--xml", type=Path, help="Path to an extracted CWE XML file")
    parser.add_argument(
        "--url",
        default=os.getenv("CWE_ZIP_URL", CWE_ZIP_URL),
        help="HTTPS CWE ZIP URL used when no local source is provided",
    )
    parser.add_argument(
        "--sha256",
        default=os.getenv("CWE_ZIP_SHA256"),
        help="Expected lowercase SHA-256 of the source ZIP archive",
    )
    parser.add_argument(
        "--cwe",
        action="append",
        dest="selected_ids",
        help="Import one CWE ID; repeat for multiple IDs",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--expect-cwe-count", type=_positive_count)
    parser.add_argument("--expect-child-of-count", type=_positive_count)
    parser.add_argument("--expect-mitigation-count", type=_positive_count)
    parser.add_argument("--uri", default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    parser.add_argument("--user", default=os.getenv("NEO4J_USER", "neo4j"))
    parser.add_argument("--database", default=os.getenv("NEO4J_DATABASE", "neo4j"))
    return parser


def _assert_expected_counts(catalog: ParsedCatalog, args: argparse.Namespace) -> None:
    checks = {
        "cweCount": args.expect_cwe_count,
        "childOfCount": args.expect_child_of_count,
        "mitigationCount": args.expect_mitigation_count,
    }
    summary = catalog.summary()
    for key, expected in checks.items():
        if expected is not None and summary[key] != expected:
            raise CatalogError(
                f"catalog {key} mismatch: expected {expected}, observed {summary[key]}"
            )


def run(argv: Sequence[str] | None = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    expected_sha256 = _validate_expected_sha256(args.sha256)
    if args.xml is not None:
        if expected_sha256 is not None:
            parser.error("--sha256 applies to ZIP input and cannot be used with --xml")
        xml_bytes = _read_bounded_file(args.xml, MAX_XML_BYTES)
        source_sha256 = hashlib.sha256(xml_bytes).hexdigest()
    else:
        if args.archive is not None:
            archive_bytes = _read_bounded_file(args.archive, MAX_ARCHIVE_BYTES)
        else:
            archive_bytes = download_archive(args.url)
        xml_bytes, source_sha256 = extract_catalog_xml(
            archive_bytes, expected_sha256=expected_sha256
        )

    catalog = parse_catalog(
        xml_bytes,
        source_sha256=source_sha256,
        selected_ids=args.selected_ids,
    )
    _assert_expected_counts(catalog, args)

    output = {"source": catalog.summary(), "dryRun": args.dry_run}
    if not args.dry_run:
        password = os.getenv("NEO4J_PASSWORD", "")
        if not password:
            parser.error("NEO4J_PASSWORD is required unless --dry-run is used")
        output["persisted"] = load_catalog(
            catalog,
            uri=args.uri,
            user=args.user,
            password=password,
            database=args.database,
        )

    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


def main() -> int:
    try:
        return run()
    except (CatalogError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
