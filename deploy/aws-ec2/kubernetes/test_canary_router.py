import copy
import unittest
from canary_router import weights, configuration


class RouteBoundary(unittest.TestCase):
    def test_rejects_foreign_targets_and_unbounded_weights(self):
        valid = {'metadata': {'name': 'api-canary', 'namespace': 'aegisai-private'},
            'spec': {'weighted': {'services': [{'name': 'api-canary-stable', 'port': 3000, 'weight': 90},
                {'name': 'api-canary-candidate', 'port': 3000, 'weight': 10}]}}}
        self.assertEqual(weights(valid)['api-canary-candidate'], 10)
        for key, value in [('name', 'foreign-service'), ('port', 80), ('weight', True), ('weight', 101), ('url', 'http://169.254.169.254')]:
            changed = copy.deepcopy(valid); changed['spec']['weighted']['services'][1][key] = value
            with self.assertRaises(AssertionError): weights(changed)
        changed = copy.deepcopy(valid); changed['spec']['weighted']['services'][0]['weight'] = 100
        with self.assertRaises(AssertionError): weights(changed)
        config = configuration(weights(valid))
        self.assertEqual(config['http']['services']['stable']['loadBalancer']['servers'], [{'url': 'http://10.45.0.65:3000'}])


if __name__ == '__main__': unittest.main()
