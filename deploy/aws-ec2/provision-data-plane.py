"""Idempotent private data-plane provisioning using the existing operator login.
No EC2, task, NAT or cluster is created. Secret request files use root-only RAM.
Default mode writes a non-secret plan. --apply performs the authorized deployment.
"""
import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import tempfile
import uuid

ACCOUNT='024139495514'
REGION='ap-northeast-2'
INSTANCE='i-0d24d0502cfc5a9c5'
BUCKET='aegisai-private-'+ACCOUNT+'-apne2'
ROLE='aegisai-private-runtime'
SECRET_NAMES={'auth':'aegisai/private-runtime/auth','scm':'aegisai/private-runtime/scm'}
ROOT=pathlib.Path('/opt/aegisai')
CLI=str(ROOT/'operator/aws-cli.sh')
TAGS=[{'Key':'Project','Value':'AegisAI'},{'Key':'ManagedBy','Value':'aegisai-v2'}]
assert os.geteuid()==0
os.umask(0o077)


def aws(service,operation,parameters=None,*,missing=()):
    command=[CLI,service,operation,'--output','json']
    temporary=None
    try:
        if parameters is not None:
            directory=pathlib.Path('/dev/shm/aegisai-aws-input');directory.mkdir(mode=0o700,exist_ok=True)
            descriptor,name=tempfile.mkstemp(prefix='request-',suffix='.json',dir=directory)
            temporary=pathlib.Path(name)
            with os.fdopen(descriptor,'w') as output:json.dump(parameters,output)
            command+=['--cli-input-json','file:///run/aws-input/'+temporary.name]
        result=subprocess.run(command,capture_output=True,timeout=60)
    finally:
        if temporary is not None: temporary.unlink(missing_ok=True)
    if result.returncode:
        match=re.search(rb'An error occurred \(([A-Za-z0-9_.-]+)\)',result.stderr)
        code=match.group(1).decode() if match else 'OPERATION_FAILED'
        if code in missing: return None
        raise RuntimeError('AWS_OPERATION_FAILED:'+service+':'+operation+':'+code)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def owned(tags):
    values={item['Key']:item['Value'] for item in tags}
    return values.get('Project')=='AegisAI' and values.get('ManagedBy')=='aegisai-v2'


def secret_values():
    if (ROOT/'operator/data-plane-state.json').is_file():
        from managed_runtime import load_bundles
        _, bundles = load_bundles(ROOT)
        return bundles
    values={}
    for line in (ROOT/'shared/runtime.env').read_text().splitlines():
        if '=' not in line or line.lstrip().startswith('#'): continue
        key,value=line.split('=',1);value=value.strip()
        if len(value)>1 and value[0]==value[-1] and value[0] in ('"',"'"):value=value[1:-1]
        values[key.strip()]=value
    auth_keys=['DATABASE_URL','REDIS_URL','SESSION_SECRET','CSRF_SECRET','GITHUB_CLIENT_ID','GITHUB_CLIENT_SECRET',
        'GITHUB_LOGIN_KIND','ALLOWED_GITHUB_USER_IDS','GITLAB_CLIENT_ID','GITLAB_CLIENT_SECRET','APP_URL','FRONTEND_URL',
        'SESSION_COOKIE_NAME','CSRF_COOKIE_NAME','COOKIE_DOMAIN','COOKIE_SECURE','SESSION_TTL_SECONDS','THROTTLE_TTL_MS',
        'THROTTLE_LIMIT','TOKEN_ENCRYPTION_KEY','INTERNAL_API_SECRET','REPORT_STORAGE_PATH','REPORT_EXPIRY_HOURS']
    auth={key:values[key] for key in auth_keys if key in values}
    auth.update(USE_INTERNAL_AI='false',ANALYSIS_CLIENT_MODE='internal')
    scm={key:values[key] for key in ['DATABASE_URL','GITHUB_APP_ID','GITHUB_APP_SLUG','ALLOWED_GITHUB_USER_IDS'] if key in values}
    scm['GITHUB_APP_PRIVATE_KEY_PEM']=(ROOT/'shared/scm-keys/github-app-org.pem').read_text()
    assert all(key in auth for key in ['DATABASE_URL','SESSION_SECRET','GITHUB_CLIENT_SECRET'])
    assert 'PRIVATE KEY' in scm['GITHUB_APP_PRIVATE_KEY_PEM']
    return {'auth':auth,'scm':scm}


def main():
    identity=aws('sts','get-caller-identity')
    assert identity['Account']==ACCOUNT
    instance=aws('ec2','describe-instances',{'InstanceIds':[INSTANCE]})['Reservations'][0]['Instances'][0]
    assert instance['InstanceId']==INSTANCE and instance['State']['Name']=='running'
    current_profile=instance.get('IamInstanceProfile',{}).get('Arn')
    assert current_profile in (None,f'arn:aws:iam::{ACCOUNT}:instance-profile/{ROLE}'),'Do not replace an unrelated instance profile'
    plan={'account':ACCOUNT,'region':REGION,'existingInstanceId':INSTANCE,'additionalCompute':False,
        'bucket':BUCKET,'bucketEncryption':'SSE-KMS / AWS-managed aws/s3 key','bucketKeyEnabled':False,
        'evidenceRetentionDays':7,'backupRetentionDays':14,'separateSecrets':SECRET_NAMES,
        'instanceRole':ROLE,'runtimePermissions':['selected secrets:GetSecretValue','private bucket evidence read/write/delete',
            'private backup write/read','KMS via S3 for this bucket only'],
        'runtimeEc2OrIamManagement':False,'metadataTokens':'required','metadataHopLimit':2}
    (ROOT/'operator/data-plane-plan.json').write_text(json.dumps(plan,indent=2))
    if '--apply' not in sys.argv:
        print(json.dumps(plan));return

    exists=aws('s3api','head-bucket',{'Bucket':BUCKET},missing=('404','NoSuchBucket','NotFound'))
    if exists is None:
        aws('s3api','create-bucket',{'Bucket':BUCKET,'CreateBucketConfiguration':{'LocationConstraint':REGION}})
        aws('s3api','put-bucket-tagging',{'Bucket':BUCKET,'Tagging':{'TagSet':TAGS}})
    else:
        assert owned(aws('s3api','get-bucket-tagging',{'Bucket':BUCKET})['TagSet']),'Refuse an unmanaged bucket'
    assert aws('s3api','get-bucket-versioning',{'Bucket':BUCKET}).get('Status') not in ('Enabled','Suspended'),'Evidence deletion must remove the object, not leave old versions'
    aws('s3api','put-public-access-block',{'Bucket':BUCKET,'PublicAccessBlockConfiguration':{
        'BlockPublicAcls':True,'IgnorePublicAcls':True,'BlockPublicPolicy':True,'RestrictPublicBuckets':True}})
    aws('s3api','put-bucket-ownership-controls',{'Bucket':BUCKET,'OwnershipControls':{'Rules':[{'ObjectOwnership':'BucketOwnerEnforced'}]}})
    aws('s3api','put-bucket-encryption',{'Bucket':BUCKET,'ServerSideEncryptionConfiguration':{'Rules':[{
        'ApplyServerSideEncryptionByDefault':{'SSEAlgorithm':'aws:kms'},'BucketKeyEnabled':False}]}})
    aws('s3api','put-bucket-lifecycle-configuration',{'Bucket':BUCKET,'LifecycleConfiguration':{'Rules':[
        {'ID':'evidence-defense-in-depth','Status':'Enabled','Filter':{'Prefix':'evidence/'},'Expiration':{'Days':7},'AbortIncompleteMultipartUpload':{'DaysAfterInitiation':1}},
        {'ID':'backup-retention','Status':'Enabled','Filter':{'Prefix':'backups/'},'Expiration':{'Days':14},'AbortIncompleteMultipartUpload':{'DaysAfterInitiation':1}}]}})
    # Bootstrap AWS's managed S3 KMS key without creating a charged customer key.
    existing_key=aws('kms','describe-key',{'KeyId':'alias/aws/s3'},missing=('NotFoundException',))
    if existing_key is None:
        probe='evidence/_ops/kms-'+uuid.uuid4().hex+'.json'
        transfer=subprocess.run([CLI,'s3','cp','-','s3://'+BUCKET+'/'+probe,'--sse','aws:kms','--only-show-errors'],
            input=b'{"purpose":"infrastructure-encryption-check","sourceProcessed":false}',capture_output=True,timeout=60)
        assert transfer.returncode==0,'AWS managed encryption bootstrap failed'
        head=aws('s3api','head-object',{'Bucket':BUCKET,'Key':probe})
        assert head['ServerSideEncryption']=='aws:kms'
        existing_key=aws('kms','describe-key',{'KeyId':'alias/aws/s3'})
        assert existing_key['KeyMetadata']['Arn']==head['SSEKMSKeyId']
        aws('s3api','delete-object',{'Bucket':BUCKET,'Key':probe})
    key=existing_key['KeyMetadata'];kms_arn=key['Arn']
    assert key['KeyManager']=='AWS'

    arns={}
    for kind,values in secret_values().items():
        name=SECRET_NAMES[kind]
        previous=aws('secretsmanager','describe-secret',{'SecretId':name},missing=('ResourceNotFoundException',))
        if previous is None:
            result=aws('secretsmanager','create-secret',{'Name':name,'Description':'AegisAI private runtime '+kind+' credentials',
                'SecretString':json.dumps({'version':1,'values':values}),'Tags':TAGS})
        else:
            assert owned(previous.get('Tags',[])),'Refuse an unmanaged secret'
            result=aws('secretsmanager','put-secret-value',{'SecretId':name,'SecretString':json.dumps({'version':1,'values':values})})
        arns[kind]=result['ARN']
    trust={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'ec2.amazonaws.com'},'Action':'sts:AssumeRole'}]}
    role=aws('iam','get-role',{'RoleName':ROLE},missing=('NoSuchEntity',))
    if role is None: aws('iam','create-role',{'RoleName':ROLE,'AssumeRolePolicyDocument':json.dumps(trust),'Tags':TAGS})
    else:
        assert owned(role['Role'].get('Tags',[])),'Refuse an unmanaged role'
        aws('iam','update-assume-role-policy',{'RoleName':ROLE,'PolicyDocument':json.dumps(trust)})
    bucket_arn='arn:aws:s3:::'+BUCKET
    policy={'Version':'2012-10-17','Statement':[
        {'Effect':'Allow','Action':['secretsmanager:GetSecretValue'],'Resource':list(arns.values())},
        {'Effect':'Allow','Action':['s3:ListBucket'],'Resource':bucket_arn},
        {'Effect':'Allow','Action':['s3:GetObject','s3:PutObject','s3:DeleteObject'],'Resource':bucket_arn+'/evidence/*'},
        {'Effect':'Allow','Action':['s3:GetObject','s3:PutObject'],'Resource':bucket_arn+'/backups/*'},
        {'Effect':'Allow','Action':['kms:GenerateDataKey','kms:Decrypt'],'Resource':kms_arn,'Condition':{
            'StringEquals':{'kms:ViaService':f's3.{REGION}.amazonaws.com','kms:CallerAccount':ACCOUNT},
            'StringLike':{'kms:EncryptionContext:aws:s3:arn':[bucket_arn+'/evidence/*',bucket_arn+'/backups/*']}}}]}
    (ROOT/'operator/runtime-role-policy.json').write_text(json.dumps(policy,indent=2))
    aws('iam','put-role-policy',{'RoleName':ROLE,'PolicyName':'AegisAIPrivateDataPlane','PolicyDocument':json.dumps(policy)})
    profile=aws('iam','get-instance-profile',{'InstanceProfileName':ROLE},missing=('NoSuchEntity',))
    if profile is None:
        aws('iam','create-instance-profile',{'InstanceProfileName':ROLE,'Tags':TAGS})
        aws('iam','add-role-to-instance-profile',{'InstanceProfileName':ROLE,'RoleName':ROLE})
    else:
        assert owned(profile['InstanceProfile'].get('Tags',[])) and [entry['RoleName'] for entry in profile['InstanceProfile']['Roles']]==[ROLE]
    bucket_policy={'Version':'2012-10-17','Statement':[
        {'Sid':'DenyPlainTransport','Effect':'Deny','Principal':'*','Action':'s3:*','Resource':[bucket_arn,bucket_arn+'/*'],'Condition':{'Bool':{'aws:SecureTransport':'false'}}},
        {'Sid':'RequireKmsForWrites','Effect':'Deny','Principal':'*','Action':'s3:PutObject','Resource':bucket_arn+'/*','Condition':{'StringNotEquals':{'s3:x-amz-server-side-encryption':'aws:kms'}}},
        {'Sid':'RequireCreateOnlyWrites','Effect':'Deny','Principal':'*','Action':'s3:PutObject','Resource':bucket_arn+'/*','Condition':{'Null':{'s3:if-none-match':'true'}}}
    ]}
    aws('s3api','put-bucket-policy',{'Bucket':BUCKET,'Policy':json.dumps(bucket_policy)})
    if current_profile is None:
        for attempt in range(8):
            try:
                aws('ec2','associate-iam-instance-profile',{'InstanceId':INSTANCE,'IamInstanceProfile':{'Name':ROLE}})
                break
            except RuntimeError as error:
                if not str(error).endswith(':InvalidParameterValue') or attempt==7: raise
                time.sleep(3)
    aws('ec2','modify-instance-metadata-options',{'InstanceId':INSTANCE,'HttpTokens':'required','HttpEndpoint':'enabled','HttpPutResponseHopLimit':2})
    state={**plan,'secretArns':arns,'kmsKeyArn':kms_arn,'policy':policy}
    (ROOT/'operator/data-plane-state.json').write_text(json.dumps(state,indent=2))
    print(json.dumps({'dataPlaneProvisioned':True,'additionalCompute':False,'secrets':2,'publicBucketAccess':False,
        'kmsKeyManager':'AWS','runtimeEc2OrIamManagement':False,'evidenceBucket':BUCKET}))


if __name__=='__main__': main()
