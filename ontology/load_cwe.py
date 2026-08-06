import io, zipfile, requests
from lxml import etree
from neo4j import GraphDatabase

# ── 설정 ──────────────────────────────────────────────
CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NEO4J_URI   = "bolt://localhost:7687"
NEO4J_AUTH  = ("neo4j", "aegisai123")
CWE_FILTER  = None   # None = 전체 적재
# ─────────────────────────────────────────────────────

def download_xml() -> bytes:
    print("CWE XML 다운로드 중...")
    r = requests.get(CWE_ZIP_URL, timeout=120)
    r.raise_for_status()
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
    print(f"  → {xml_name}")
    return zf.read(xml_name)

def parse(xml_bytes: bytes):
    root = etree.fromstring(xml_bytes)
    ns = {"cwe": root.nsmap[None]}
    cwes, rels, mits = [], [], []

    for w in root.findall(".//cwe:Weaknesses/cwe:Weakness", ns):
        wid = w.get("ID")
        if CWE_FILTER and wid not in CWE_FILTER:
            continue

        desc_el = w.find("cwe:Description", ns)
        cwes.append({
            "id": f"CWE-{wid}",
            "name": w.get("Name"),
            "abstraction": w.get("Abstraction"),
            "likelihood": w.findtext("cwe:Likelihood_Of_Exploit",
                                     default="", namespaces=ns),
            "description": " ".join(desc_el.itertext()).strip()
                           if desc_el is not None else "",
        })

        for rw in w.findall(".//cwe:Related_Weaknesses/cwe:Related_Weakness", ns):
            if rw.get("Nature") in ("ChildOf", "PeerOf"):
                rels.append({
                    "src": f"CWE-{wid}",
                    "dst": f"CWE-{rw.get('CWE_ID')}",
                    "nature": rw.get("Nature"),
                })

        for i, m in enumerate(
                w.findall(".//cwe:Potential_Mitigations/cwe:Mitigation", ns)):
            d = m.find("cwe:Description", ns)
            mits.append({
                "id": f"CWE-{wid}-M{i}",
                "cwe": f"CWE-{wid}",
                "phase": m.findtext("cwe:Phase", default="", namespaces=ns),
                "description": (" ".join(d.itertext()).strip()[:1000]
                                if d is not None else ""),
            })

    print(f"파싱 완료: CWE {len(cwes)}개, 관계 {len(rels)}개, 완화기법 {len(mits)}개")
    return cwes, rels, mits

def load(cwes, rels, mits):
    driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    with driver.session() as s:
        s.run("CREATE CONSTRAINT cwe_id IF NOT EXISTS "
              "FOR (c:CWE) REQUIRE c.id IS UNIQUE")
        s.run("CREATE CONSTRAINT mit_id IF NOT EXISTS "
              "FOR (m:Mitigation) REQUIRE m.id IS UNIQUE")

        s.run("""
            UNWIND $rows AS row
            MERGE (c:CWE {id: row.id})
            SET c.name = row.name,
                c.abstraction = row.abstraction,
                c.likelihood = row.likelihood,
                c.description = row.description
        """, rows=cwes)

        s.run("""
            UNWIND $rows AS row
            MATCH (a:CWE {id: row.src}), (b:CWE {id: row.dst})
            FOREACH (_ IN CASE WHEN row.nature = 'ChildOf'
                     THEN [1] ELSE [] END |
                MERGE (a)-[:CHILD_OF]->(b))
            FOREACH (_ IN CASE WHEN row.nature = 'PeerOf'
                     THEN [1] ELSE [] END |
                MERGE (a)-[:PEER_OF]->(b))
        """, rows=rels)

        s.run("""
            UNWIND $rows AS row
            MATCH (c:CWE {id: row.cwe})
            MERGE (m:Mitigation {id: row.id})
            SET m.phase = row.phase, m.description = row.description
            MERGE (c)-[:MITIGATED_BY]->(m)
        """, rows=mits)
    driver.close()
    print("적재 완료")

if __name__ == "__main__":
    load(*parse(download_xml()))
