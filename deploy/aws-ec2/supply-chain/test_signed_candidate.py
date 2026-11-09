"""Actual signature rejection using CI-issued bundles, not mocked crypto."""
import argparse
import json
import os
from pathlib import Path
import tempfile

from policy import digest, strict_json
from verify_candidate import cryptographic_verify, verify


def main():
    assert os.environ.get('GITHUB_ACTIONS') == 'true'
    parser = argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    args = parser.parse_args()
    directory = args.directory
    manifest = strict_json(directory/'candidate.json')
    expected = digest(directory/'candidate.json')
    verify(directory,expected,os.environ['GITHUB_SHA'])
    rejected = []
    with tempfile.TemporaryDirectory() as temporary:
        changed = Path(temporary)/'candidate.json'
        changed.write_bytes((directory/'candidate.json').read_bytes()+b'\n')
        for name,path,source in [('modified-subject',changed,os.environ['GITHUB_SHA']),
                                 ('wrong-approved-source',directory/'candidate.json','0'*40)]:
            try:
                cryptographic_verify(path,directory/'provenance.sigstore.json',source)
            except ValueError:
                rejected.append(name)
            else:
                raise AssertionError('Invalid attestation accepted: '+name)
    with tempfile.TemporaryDirectory() as temporary:
        bad = strict_json(directory/'provenance.sigstore.json')
        signature = bad['dsseEnvelope']['signatures'][0]['sig']
        bad['dsseEnvelope']['signatures'][0]['sig'] = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        path = Path(temporary)/'altered-signature.json'
        path.write_text(json.dumps(bad))
        try:
            cryptographic_verify(directory/'candidate.json',path,os.environ['GITHUB_SHA'])
        except ValueError:
            rejected.append('altered-signature')
        else:
            raise AssertionError('Altered signature accepted')
    bundle = directory/'api-sbom.sigstore.json'
    saved = bundle.read_bytes()
    bundle.unlink()
    try:
        try:
            verify(directory,expected,os.environ['GITHUB_SHA'])
        except (ValueError,OSError):
            rejected.append('missing-sbom-attestation')
        else:
            raise AssertionError('Missing SBOM attestation accepted')
    finally:
        bundle.write_bytes(saved)
    print(json.dumps({'actualSignedCandidateVerification':'passed','actualCryptographicRejectCases':rejected,
                      'productionChanged':False,'sourceCommit':manifest['sourceCommit']}))


if __name__ == '__main__':
    main()
