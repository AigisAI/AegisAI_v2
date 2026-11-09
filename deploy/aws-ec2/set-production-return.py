"""Update only the identity return URL in the existing managed Auth secret.
Uses operator authorization for PutSecretValue; secret JSON lives in RAM only.
"""
import json
import os
import pathlib
import subprocess
import tempfile
import uuid

assert os.geteuid()==0
os.umask(0o077)
root=pathlib.Path('/opt/aegisai')
state=json.loads((root/'operator/data-plane-state.json').read_text())
cli=str(root/'operator/aws-cli.sh')
secret_id=state['secretArns']['auth']
result=subprocess.run([cli,'secretsmanager','get-secret-value','--secret-id',secret_id,'--output','json'],capture_output=True,timeout=60)
assert result.returncode==0,'Managed authentication configuration could not be read'
secret=json.loads(json.loads(result.stdout)['SecretString'])
assert secret['version']==1 and secret['values']['ALLOWED_GITHUB_USER_IDS']=='161540124'
origin='https://aegisai-aws.tailaca7d2.ts.net'
assert secret['values']['FRONTEND_URL'] in (origin,origin+'/',origin+'/auth-check')
if secret['values']['FRONTEND_URL']!=origin+'/':
    secret['values']['FRONTEND_URL']=origin+'/'
    directory=pathlib.Path('/dev/shm/aegisai-aws-input');directory.mkdir(mode=0o700,exist_ok=True)
    descriptor,name=tempfile.mkstemp(prefix='login-return-',suffix='.json',dir=directory)
    temporary=pathlib.Path(name)
    try:
        with os.fdopen(descriptor,'w') as output:
            json.dump({'SecretId':secret_id,'SecretString':json.dumps(secret),'ClientRequestToken':str(uuid.uuid4())},output)
        changed=subprocess.run([cli,'secretsmanager','put-secret-value','--cli-input-json','file:///run/aws-input/'+temporary.name],capture_output=True,timeout=60)
        assert changed.returncode==0,'Managed authentication return URL update failed'
    finally:temporary.unlink(missing_ok=True)
print('MANAGED_LOGIN_RETURN_SET_TO_PRIVATE_APPLICATION')
