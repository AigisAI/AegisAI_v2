"""Reject infrastructure mutation; never apply a plan or expose resource values."""
import json
import re

if not __debug__:
    raise RuntimeError("TERRAFORM_SAFETY_CHECKS_MUST_BE_ENABLED")


def validate_no_changes(plan):
    changes = [{'address': item['address'], 'actions': item['change']['actions']}
               for item in plan.get('resource_changes', [])
               if item['change']['actions'] != ['no-op']]
    if changes:
        raise ValueError('CLOUD_MUTATION_NOT_AUTHORIZED: ' + json.dumps(changes))
    if plan.get('errored') or plan.get('complete') is False:
        raise ValueError('PLAN_INCOMPLETE')
    return True


def assert_no_secret_values(value):
    encoded = json.dumps(value)
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:AKIA|ASIA)[A-Z0-9]{16}', encoded):
        raise ValueError('SECRET_MATERIAL_IN_TERRAFORM_STATE')
    forbidden = {'secret_string', 'secret_binary', 'access_key', 'secret_key', 'session_token',
                 'password', 'private_key', 'user_data', 'user_data_base64'}
    def visit(item):
        if isinstance(item, dict):
            for key, content in item.items():
                if key.lower() in forbidden and content not in (None, '', [], {}):
                    raise ValueError('SECRET_OR_USERDATA_FIELD_IN_STATE: ' + key)
                visit(content)
        elif isinstance(item, list):
            for content in item:
                visit(content)
    visit(value)
