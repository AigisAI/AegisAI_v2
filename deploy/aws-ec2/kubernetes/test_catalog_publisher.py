import datetime
import unittest
from catalog_publisher import bounded_status


class Publisher(unittest.TestCase):
    def test_preserves_source_time_drops_extra_data_and_refuses_stale_ready(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        value={'ready':True,'busy':False,'ai':'DISABLED','updatedAt':now.isoformat(),
            'scannerSetVersion':'java-v1:'+'a'*16+':'+'b'*64,'policyVersion':'private-java-v1',
            'unexpectedPrivateField':'not-for-publication'}
        result=bounded_status(value,now)
        self.assertEqual(result['updatedAt'],value['updatedAt'])
        self.assertNotIn('unexpectedPrivateField',result)
        with self.assertRaises(AssertionError):bounded_status(value,now+datetime.timedelta(seconds=61))
        with self.assertRaises(AssertionError):bounded_status(dict(value,ready='true'),now)
        with self.assertRaises(AssertionError):bounded_status(dict(value,ai='ENABLED'),now)


if __name__=='__main__':unittest.main()
