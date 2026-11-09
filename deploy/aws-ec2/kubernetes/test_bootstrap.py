import copy
import unittest
from bootstrap import validate


class Preflight(unittest.TestCase):
    def test_rejects_wrong_host_capacity_busy_scanner_and_route_overlap(self):
        facts = {'instanceId': 'i-0d24d0502cfc5a9c5', 'cpuCount': 2, 'architecture': 'x86_64',
                 'memoryAvailableMiB': 5000, 'diskFreeBytes': 10 * 1024**3,
                 'scannerReady': True, 'scannerBusy': False,
                 'addresses': ['172.31.55.151'], 'routes': ['default', '172.18.0.0/16']}
        validate(facts)
        for key, value in [('instanceId', 'other'), ('memoryAvailableMiB', 4095),
                           ('diskFreeBytes', 5 * 1024**3), ('scannerBusy', True),
                           ('addresses', ['127.0.0.1']), ('routes', ['10.0.0.0/8'])]:
            with self.subTest(key=key):
                changed = copy.deepcopy(facts)
                changed[key] = value
                with self.assertRaises(AssertionError):
                    validate(changed)


if __name__ == '__main__':
    unittest.main()
