"""Operator-only health. Never export credential values into status/logs."""
import datetime
import json
import os
from pathlib import Path
import subprocess


def main():
    assert os.geteuid()==0
    os.umask(0o077)
    result=subprocess.run(['/opt/aegisai/operator/aws-cli.sh','sts','get-caller-identity'],
        capture_output=True,text=True,timeout=35)
    state='unavailable'
    if result.returncode==0:
        identity=json.loads(result.stdout)
        state='connected' if identity['Account']=='024139495514' and identity['Arn']=='arn:aws:iam::024139495514:user/goodtu02' else 'wrong-principal'
    elif 'login' in result.stderr.lower() or 'expired' in result.stderr.lower():state='needs-login'
    value={'state':state,'checkedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'credentialValuesPrinted':False,'newAccessKeysCreated':False}
    Path('/opt/aegisai/operator/authentication-status.json').write_text(json.dumps(value))
    print(json.dumps(value))


if __name__=='__main__':main()
