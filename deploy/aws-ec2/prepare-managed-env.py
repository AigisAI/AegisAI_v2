"""Write secret references only; decrypted application values are never exported."""
import json
import os
import pathlib

assert os.geteuid()==0
os.umask(0o077)
root=pathlib.Path('/opt/aegisai')
state=json.loads((root/'operator/data-plane-state.json').read_text())
common={'NODE_ENV':'production','PORT':'3000','AWS_REGION':'ap-northeast-2','AWS_EC2_METADATA_V1_DISABLED':'true',
    'EVIDENCE_BUCKET':state['bucket'],'EVIDENCE_KMS_KEY_ARN':state['kmsKeyArn']}
api={**common,'AWS_AUTH_SECRET_ARN':state['secretArns']['auth'],'AWS_SCM_SECRET_ARN':state['secretArns']['scm'],
    'ALLOWED_GITHUB_USER_IDS':'161540124','GITHUB_LOGIN_KIND':'github-app'}
broker={**common,'AWS_SCM_SECRET_ARN':state['secretArns']['scm']}
for name,values in [('runtime-public.env',api),('private-broker-public.env',broker)]:
    assert all(value and not any(char in value for char in '\r\n\0') for value in values.values())
    pending=root/'shared'/(name+'.pending')
    pending.write_text(''.join(key+'='+value+'\n' for key,value in values.items()))
    pending.chmod(0o600);pending.replace(root/'shared'/name)
retention=pathlib.Path('/run/aegisai-retention');retention.mkdir(mode=0o700,exist_ok=True)
assert retention.resolve()==retention and retention.stat().st_uid==0
print('MANAGED_SECRET_REFERENCES_PREPARED_NO_SECRET_VALUES')
