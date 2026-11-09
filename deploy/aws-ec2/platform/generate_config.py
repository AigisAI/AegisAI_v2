"""Adopt observed resources without secret values or new cloud topology."""
import argparse
import json
import pathlib


ACCOUNT = '024139495514'
INSTANCE = 'i-0d24d0502cfc5a9c5'


def configuration(inventory, toolchain):
    assert inventory['account'] == ACCOUNT
    instance = inventory['instance']
    assert instance['InstanceId'] == INSTANCE
    assert inventory['instanceUserData']['emptyVerified'], 'NONEMPTY_USER_DATA_EXCLUDED'
    group = inventory['securityGroups'][0]['SecurityGroups'][0]
    volume = inventory['volumes'][0]['Volumes'][0]
    assert volume['Encrypted'] and not volume['Attachments'][0]['DeleteOnTermination']
    assert group['IpPermissions'] == [], 'PUBLIC_INGRESS_NOT_APPROVED'
    assert len(instance['SecurityGroups']) == 1
    profile = inventory['iam']['instanceProfile']['InstanceProfile']
    assert len(profile['Roles']) == 1
    role_name = profile['Roles'][0]['RoleName']
    role = inventory['iam'][role_name]['role']['Role']
    assert not inventory['iam'][role_name]['attached']['AttachedPolicies']
    tags = lambda values: {tag['Key']: tag['Value'] for tag in values}
    resources = {}
    imports = {}

    def resource(kind, name, identity, attributes):
        attributes['lifecycle'] = {'prevent_destroy': True}
        resources.setdefault(kind, {})[name] = attributes
        imports[kind + '.' + name] = identity

    resource('aws_security_group', 'control', group['GroupId'], {
        'name': group['GroupName'], 'description': group['Description'],
        'vpc_id': group['VpcId'], 'tags': tags(group.get('Tags', [])),
        'ingress': [], 'egress': [{'protocol': '-1', 'from_port': 0, 'to_port': 0,
            'description': '', 'cidr_blocks': ['0.0.0.0/0'], 'ipv6_cidr_blocks': [],
            'prefix_list_ids': [], 'security_groups': [], 'self': False}]})
    assert group['IpPermissionsEgress'] == [{'IpProtocol': '-1', 'UserIdGroupPairs': [],
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}], 'Ipv6Ranges': [], 'PrefixListIds': []}]
    resource('aws_iam_role', 'runtime', role_name, {
        'name': role_name, 'path': role['Path'],
        'assume_role_policy': json.dumps(role['AssumeRolePolicyDocument']),
        'max_session_duration': role['MaxSessionDuration'], 'tags': tags(role.get('Tags', []))})
    resource('aws_iam_instance_profile', 'runtime', profile['InstanceProfileName'], {
        'name': profile['InstanceProfileName'], 'path': profile['Path'],
        'role': '${aws_iam_role.runtime.name}', 'tags': tags(profile.get('Tags', []))})
    for index, (name, value) in enumerate(inventory['iam'][role_name]['inline'].items()):
        resource('aws_iam_role_policy', 'runtime_' + str(index), role_name + ':' + name,
                 {'name': name, 'role': '${aws_iam_role.runtime.id}',
                  'policy': json.dumps(value['PolicyDocument'])})
    metadata = instance['MetadataOptions']
    root_device = {'delete_on_termination': False, 'encrypted': True,
        'volume_size': volume['Size'], 'volume_type': volume['VolumeType'],
        'iops': volume['Iops'], 'throughput': volume['Throughput'],
        'kms_key_id': volume['KmsKeyId'], 'tags': tags(volume.get('Tags', []))}
    resource('aws_instance', 'control', INSTANCE, {
        'ami': instance['ImageId'], 'instance_type': instance['InstanceType'],
        'subnet_id': instance['SubnetId'], 'availability_zone': instance['Placement']['AvailabilityZone'],
        'private_ip': instance['PrivateIpAddress'], 'key_name': instance['KeyName'],
        'associate_public_ip_address': bool(instance['NetworkInterfaces'][0].get('Association')),
        'vpc_security_group_ids': ['${aws_security_group.control.id}'],
        'iam_instance_profile': '${aws_iam_instance_profile.runtime.name}',
        'monitoring': instance['Monitoring']['State'] == 'enabled',
        'ebs_optimized': instance['EbsOptimized'], 'source_dest_check': instance['SourceDestCheck'],
        'disable_api_termination': instance['DisableApiTermination'],
        'metadata_options': {'http_endpoint': metadata['HttpEndpoint'],
            'http_tokens': metadata['HttpTokens'], 'http_put_response_hop_limit': metadata['HttpPutResponseHopLimit'],
            'http_protocol_ipv6': metadata['HttpProtocolIpv6'], 'instance_metadata_tags': metadata['InstanceMetadataTags']},
        'root_block_device': root_device, 'tags': tags(instance.get('Tags', []))})
    bucket = 'aegisai-private-' + ACCOUNT + '-apne2'
    s3 = inventory['s3']
    resource('aws_s3_bucket', 'private', bucket, {
        'bucket': bucket, 'force_destroy': False,
        'tags': tags(s3['get-bucket-tagging']['TagSet'])})
    ref = '${aws_s3_bucket.private.id}'
    resource('aws_s3_bucket_policy', 'private', bucket, {
        'bucket': ref, 'policy': s3['get-bucket-policy']['Policy']})
    resource('aws_s3_bucket_public_access_block', 'private', bucket, {
        'bucket': ref, 'block_public_acls': True, 'block_public_policy': True,
        'ignore_public_acls': True, 'restrict_public_buckets': True})
    assert all(s3['get-public-access-block']['PublicAccessBlockConfiguration'].values())
    encryption = s3['get-bucket-encryption']['ServerSideEncryptionConfiguration']['Rules']
    assert len(encryption) == 1 and encryption[0]['ApplyServerSideEncryptionByDefault'] == {'SSEAlgorithm': 'aws:kms'}
    resource('aws_s3_bucket_server_side_encryption_configuration', 'private', bucket, {
        'bucket': ref, 'rule': [{'apply_server_side_encryption_by_default': {'sse_algorithm': 'aws:kms'},
                              'bucket_key_enabled': encryption[0]['BucketKeyEnabled']}]})
    resource('aws_s3_bucket_ownership_controls', 'private', bucket, {
        'bucket': ref, 'rule': {'object_ownership': s3['get-bucket-ownership-controls']['OwnershipControls']['Rules'][0]['ObjectOwnership']}})
    lifecycle = s3['get-bucket-lifecycle-configuration']
    rules = [{'id': item['ID'], 'status': item['Status'], 'filter': {'prefix': item['Filter']['Prefix']},
              'expiration': {'days': item['Expiration']['Days']},
              'abort_incomplete_multipart_upload': {'days_after_initiation': item['AbortIncompleteMultipartUpload']['DaysAfterInitiation']}}
             for item in lifecycle['Rules']]
    resource('aws_s3_bucket_lifecycle_configuration', 'private', bucket, {
        'bucket': ref, 'transition_default_minimum_object_size': lifecycle['TransitionDefaultMinimumObjectSize'], 'rule': rules})
    assert not s3['get-bucket-versioning'], 'VERSIONING_CONFIG_NEEDS_REVIEW'
    resource('aws_s3_bucket_versioning', 'private', bucket, {
        'bucket': ref, 'versioning_configuration': {'status': 'Disabled'}})
    config = {'terraform': {'required_version': '= ' + toolchain['terraformVersion'],
        'required_providers': {'aws': {'source': 'hashicorp/aws', 'version': '= ' + toolchain['awsProviderVersion']}},
        'backend': {'local': {'path': 'state/terraform.tfstate'}}},
        'provider': {'aws': {'region': 'ap-northeast-2', 'allowed_account_ids': [ACCOUNT]}},
        'resource': resources}
    return config, imports


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('inventory', type=pathlib.Path)
    parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    config, imports = configuration(json.loads(args.inventory.read_text()),
                                    json.loads(pathlib.Path(__file__).with_name('toolchain.json').read_text()))
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'main.tf.json').write_text(json.dumps(config, indent=2) + '\n')
    (args.output / 'imports.json').write_text(json.dumps(imports, indent=2) + '\n')
    print(json.dumps({'terraformConfigurationGenerated': True, 'resources': len(imports), 'secretValuesIncluded': False}))
