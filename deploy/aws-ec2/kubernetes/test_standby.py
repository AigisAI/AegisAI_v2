from pathlib import Path
import tempfile
import unittest
from standby import public_environment


class PublicConfiguration(unittest.TestCase):
    def test_secret_values_are_never_copied_into_public_configmap(self):
        environment={'NODE_ENV':'production','PORT':'3000','AWS_REGION':'ap-northeast-2',
            'AWS_AUTH_SECRET_ARN':'arn:aws:secretsmanager:ap-northeast-2:024139495514:secret:aegisai/private-runtime/auth-fixture',
            'AWS_SCM_SECRET_ARN':'arn:aws:secretsmanager:ap-northeast-2:024139495514:secret:aegisai/private-runtime/scm-fixture',
            'EVIDENCE_BUCKET':'aegisai-private-024139495514-apne2',
            'EVIDENCE_KMS_KEY_ARN':'arn:aws:kms:ap-northeast-2:024139495514:key/'+'a'*36,
            'APP_URL':'https://aegisai-aws.tailaca7d2.ts.net','FRONTEND_URL':'https://aegisai-aws.tailaca7d2.ts.net',
            'USE_INTERNAL_AI':'false','COOKIE_SECURE':'true'}
        text='\n'.join(key+'='+value for key,value in environment.items())
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'public.env';path.write_text(text+'\nUNKNOWN_SETTING=not-published\n')
            result=public_environment(path)
            self.assertNotIn('UNKNOWN_SETTING',result)
            self.assertEqual(result['RUNTIME_CATALOG_MODE'],'projected')
            path.write_text(text+'\nSESSION_SECRET=fixture-do-not-copy\n')
            with self.assertRaises(AssertionError):public_environment(path)
            path.write_text(text.replace('auth-fixture','wrong-secret-path'))
            with self.assertRaises(AssertionError):public_environment(path)


if __name__=='__main__':unittest.main()
