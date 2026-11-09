import copy
import json
import pathlib
import unittest

from generate_config import configuration
from expand_storage import validate_expansion
from plan_guard import assert_no_secret_values, validate_no_changes


class AdoptionSafety(unittest.TestCase):
    def setUp(self):
        base = pathlib.Path(__file__).parent
        self.observed = json.loads((base / 'test/observed-resources.json').read_text())
        self.tools = json.loads((base / 'toolchain.json').read_text())

    def test_existing_assets_keep_policy_and_single_owner_of_root_disk(self):
        config, imports = configuration(self.observed, self.tools)
        resources = config['resource']
        self.assertEqual(len(imports), 12)
        self.assertNotIn('aws_ebs_volume', resources)
        self.assertNotIn('aws_secretsmanager_secret_version', resources)
        self.assertNotIn('aws_eks_cluster', resources)
        for group in resources.values():
            for resource in group.values():
                self.assertTrue(resource['lifecycle']['prevent_destroy'])
        self.assertEqual(resources['aws_security_group']['control']['ingress'], [])
        self.assertEqual(json.loads(resources['aws_s3_bucket_policy']['private']['policy']),
                         json.loads(self.observed['s3']['get-bucket-policy']['Policy']))
        assert_no_secret_values(config)

    def test_other_account_instance_userdata_or_public_ingress_is_rejected(self):
        for mutate in [lambda v: v.update(account='different'),
                       lambda v: v['instance'].update(InstanceId='i-other'),
                       lambda v: v['instanceUserData'].update(emptyVerified=False),
                       lambda v: v['securityGroups'][0]['SecurityGroups'][0].update(IpPermissions=[{}])]:
            changed = copy.deepcopy(self.observed)
            mutate(changed)
            with self.assertRaises(AssertionError):
                configuration(changed, self.tools)

    def test_plan_guard_rejects_every_mutation_including_replacement(self):
        for actions in [['create'], ['update'], ['delete'], ['delete', 'create'], ['create', 'delete']]:
            with self.assertRaisesRegex(ValueError, 'CLOUD_MUTATION_NOT_AUTHORIZED'):
                validate_no_changes({'resource_changes': [{'address': 'aws_instance.control', 'change': {'actions': actions}}]})
        self.assertTrue(validate_no_changes({'complete': True, 'resource_changes': [
            {'address': 'aws_instance.control', 'change': {'actions': ['no-op']}}]}))

    def test_incomplete_or_error_plan_is_never_noop_acceptance(self):
        for plan in [{'complete': False}, {'errored': True}]:
            with self.assertRaisesRegex(ValueError, 'PLAN_INCOMPLETE'):
                validate_no_changes(plan)

    def test_explicit_storage_approval_cannot_modify_other_attributes_or_resources(self):
        before = {'id':'i-0d24d0502cfc5a9c5', 'instance_type':'m7i-flex.large',
                  'user_data_replace_on_change':None,
                  'root_block_device':[{'volume_id':'vol-06b3fb819818cd306',
                                        'volume_size':30, 'encrypted':True}]}
        after = copy.deepcopy(before)
        after['root_block_device'][0]['volume_size'] = 50
        after['user_data_replace_on_change'] = False
        plan = {'complete':True, 'resource_changes':[{'address':'aws_instance.control',
                'change':{'actions':['update'], 'before':before, 'after':after}}]}
        validate_expansion(plan)
        for mutate in [lambda p:p['resource_changes'][0]['change']['after'].update(instance_type='m7i.large'),
                       lambda p:p['resource_changes'][0]['change'].update(actions=['delete','create']),
                       lambda p:p['resource_changes'][0]['change']['after']['root_block_device'][0].update(encrypted=False),
                       lambda p:p['resource_changes'][0]['change']['after']['root_block_device'][0].update(volume_size=100),
                       lambda p:p['resource_changes'].append({'address':'aws_s3_bucket.private','change':{'actions':['delete']}})]:
            changed = copy.deepcopy(plan)
            mutate(changed)
            with self.assertRaises(AssertionError):
                validate_expansion(changed)

    def test_secret_or_userdata_state_is_rejected_but_references_are_allowed(self):
        assert_no_secret_values({'values': {'secret_arn': 'arn:aws:secretsmanager:example', 'user_data': None}})
        for value in [{'secret_string': 'secret'}, {'user_data': 'bootstrap'},
                      {'value': '-----BEGIN PRIVATE KEY-----'}, {'value': 'ASIA' + 'A' * 16}]:
            with self.assertRaises(ValueError):
                assert_no_secret_values(value)


if __name__ == '__main__':
    unittest.main()
