import copy
import unittest
from admit_images import image_policy, retained_release


def release(source,api,web):
    return {'approvedSource':source*40,'manifestSha256':source*64,
        'verification':{'signedCandidateVerification':'passed','sourceCommit':source*40,'manifestSha256':source*64},
        'images':{'api':{'reference':'docker.io/library/aegisai-api@sha256:'+api*64},
                  'web':{'reference':'docker.io/library/aegisai-web@sha256:'+web*64}}}


class BoundedReleaseHistory(unittest.TestCase):
    def test_retains_active_source_instead_of_unpromoted_primary(self):
        active=release('a','b','c');unpromoted=release('d','e','f')
        ledger={**unpromoted,'approvedReleases':[unpromoted,active]}
        self.assertEqual(retained_release(ledger,'a'*40),active)
        policy=image_policy(unpromoted['images'],active['images'])
        self.assertIn('aegisai-api@sha256:'+'b'*64,policy['spec']['validations'][0]['expression'])
        with self.assertRaises(AssertionError):retained_release(ledger,'0'*40)

    def test_rejects_unverified_source_and_kind_substitution(self):
        active=release('a','b','c')
        changed=copy.deepcopy(active);changed['verification']['sourceCommit']='0'*40
        with self.assertRaises(AssertionError):retained_release(changed,'a'*40)
        changed=copy.deepcopy(active);changed['images']['api']=changed['images']['web']
        with self.assertRaises(AssertionError):retained_release(changed,'a'*40)


if __name__=='__main__':unittest.main()
