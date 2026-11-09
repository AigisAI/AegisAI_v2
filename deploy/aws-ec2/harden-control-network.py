"""Replace only the verified AegisAI ENI's security group; retain rollback IDs."""
import json
import os
import pathlib
import subprocess

AWS = '/opt/aegisai/operator/aws-cli.sh'
INSTANCE = 'i-0d24d0502cfc5a9c5'
VPC = 'vpc-017291900e2d9467a'
ENI = 'eni-0dd71561544403e31'
GROUP = 'aegisai-control-tailnet'


def aws(*args, payload=None):
    # This payload contains only public network configuration, never credentials.
    arguments = [json.dumps(payload) if value == 'file:///dev/stdin' and payload else value for value in args]
    result = subprocess.run([AWS, *arguments], text=True, capture_output=True, check=True)
    return json.loads(result.stdout) if result.stdout.strip() else None


os.umask(0o077)
identity = aws('sts', 'get-caller-identity')
assert identity['Account'] == '024139495514'
instance = aws('ec2', 'describe-instances', '--instance-ids', INSTANCE)['Reservations'][0]['Instances'][0]
assert instance['VpcId'] == VPC and instance['State']['Name'] == 'running'
assert instance['PublicIpAddress'] == '3.36.44.43'
assert [interface['NetworkInterfaceId'] for interface in instance['NetworkInterfaces']] == [ENI]
before = pathlib.Path('/opt/aegisai/operator/control-network-before.json')
if not before.exists():
    fd = os.open(str(before), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'instanceId': INSTANCE, 'networkInterfaceId': ENI,
                   'groupIds': [group['GroupId'] for group in instance['SecurityGroups']]}, stream)
groups = aws('ec2', 'describe-security-groups', '--filters', 'Name=vpc-id,Values=' + VPC,
             'Name=group-name,Values=' + GROUP)['SecurityGroups']
if groups:
    assert len(groups) == 1
    group_id = groups[0]['GroupId']
else:
    created = aws('ec2', 'create-security-group', '--cli-input-json', 'file:///dev/stdin', payload={
        'GroupName': GROUP, 'Description': 'AegisAI control host: tailnet access only, no public ingress',
        'VpcId': VPC, 'TagSpecifications': [{'ResourceType': 'security-group', 'Tags': [
            {'Key': 'Project', 'Value': 'AegisAI'}, {'Key': 'ManagedBy', 'Value': 'AegisAI-deployment'},
            {'Key': 'Role', 'Value': 'control-plane'}]}]
    })
    group_id = created['GroupId']
group = aws('ec2', 'describe-security-groups', '--group-ids', group_id)['SecurityGroups'][0]
assert not group['IpPermissions'], 'Refuse to attach a group with unexpected ingress'
assert any(tag == {'Key': 'ManagedBy', 'Value': 'AegisAI-deployment'} for tag in group.get('Tags', []))
aws('ec2', 'modify-network-interface-attribute', '--network-interface-id', ENI, '--groups', group_id)
interface = aws('ec2', 'describe-network-interfaces', '--network-interface-ids', ENI)['NetworkInterfaces'][0]
assert [item['GroupId'] for item in interface['Groups']] == [group_id]
print(json.dumps({'instanceId': INSTANCE, 'securityGroup': group_id, 'publicIngressRules': 0,
                  'rollbackMetadata': str(before)}))
