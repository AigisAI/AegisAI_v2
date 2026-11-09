"""Reduce trusted tool output to the private runtime-results contract.
Never return source lines, snippets, arbitrary messages or tool-supplied advice.
"""
import json

from github_fetch import safe_path, FetchFailure
from runtime import RuntimeFailure

RULES = {
    'aegisai.java.request-to-process': 'HIGH',
    'aegisai.java.request-to-statement': 'HIGH',
    'aegisai.java.weak-des-cipher': 'MEDIUM'
}


def location(value, source):
    if isinstance(value, str) and value.startswith('/input/'):
        value = value[len('/input/'):]
    try:
        safe_path(value)
    except FetchFailure:
        raise RuntimeFailure('SCANNER_OUTPUT_INVALID') from None
    file = source / value
    if not file.is_file() or file.is_symlink() or file.resolve() != file:
        raise RuntimeFailure('SCANNER_OUTPUT_INVALID')
    return value


def positive_line(value):
    if type(value) is not int or not 0 < value <= 1_000_000:
        raise RuntimeFailure('SCANNER_OUTPUT_INVALID')
    return value


def normalized_findings(output, source):
    """One bounded tool output, with each referenced location verified in sealed RAM."""
    if output.exit_code != 0:
        raise RuntimeFailure('SCANNER_FAILED')
    try:
        document = json.loads(output.stdout)
        if not isinstance(document, dict):
            raise ValueError()
        findings = []
        if output.scanner == 'OPENGREP':
            if document.get('errors'):
                raise ValueError()
            matches = document.get('results', document.get('matches'))
            if not isinstance(matches, list) or len(matches) > 1000:
                raise ValueError()
            for match in matches:
                rule = match['check_id']
                if rule not in RULES:
                    raise ValueError()
                path = location(match['path'], source)
                if not path.endswith('.java'):
                    raise ValueError()
                start, end = positive_line(match['start']['line']), positive_line(match['end']['line'])
                if end < start:
                    raise ValueError()
                # Inline nosemgrep is not an authoritative product waiver.
                findings.append({'scanner':'OPENGREP','ruleId':rule,'severity':RULES[rule],
                    'filePath':path,'lineStart':start,'lineEnd':end})
        elif output.scanner == 'TRIVY':
            # Official JSON reporting contract: trivy.dev/docs/latest/guide/configuration/reporting/
            if document.get('SchemaVersion') != 2 or document.get('ArtifactType') != 'filesystem':
                raise ValueError()
            results = document.get('Results') or []
            if not isinstance(results, list) or len(results) > 1000:
                raise ValueError()
            import re
            for result in results:
                vulnerabilities = result.get('Vulnerabilities') or []
                if not isinstance(vulnerabilities,list) or len(vulnerabilities) > 1000:
                    raise ValueError()
                for vulnerability in vulnerabilities:
                    identifier, severity = vulnerability['VulnerabilityID'], vulnerability['Severity']
                    if not isinstance(identifier,str) or not re.fullmatch(r'(CVE-[0-9]{4}-[0-9]{4,12}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})',identifier):
                        raise ValueError()
                    if severity not in ('CRITICAL','HIGH','MEDIUM','LOW','INFO'):
                        raise ValueError()
                    findings.append({'scanner':'TRIVY','ruleId':identifier,'severity':severity,
                        'filePath':location(result['Target'],source),'lineStart':None,'lineEnd':None})
                    if len(findings) > 1000:
                        raise ValueError()
        elif output.scanner == 'SYFT':
            if not isinstance(document.get('artifacts'),list) or len(document['artifacts']) > 10000:
                raise ValueError()
        else:
            raise ValueError()
        # Multiple declared packages can report the same advisory at one manifest.
        # Collapse those rows rather than inventing distinct source locations.
        merged = {}
        ranks = {'INFO':0,'LOW':1,'MEDIUM':2,'HIGH':3,'CRITICAL':4}
        for finding in findings:
            key = (finding['scanner'],finding['ruleId'],finding['filePath'],finding['lineStart'],finding['lineEnd'])
            old = merged.get(key)
            if old is None or ranks[finding['severity']] > ranks[old['severity']]: merged[key] = finding
        return list(merged.values())
    except RuntimeFailure:
        raise
    except Exception:
        raise RuntimeFailure('SCANNER_OUTPUT_INVALID') from None
