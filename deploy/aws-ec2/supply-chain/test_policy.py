import copy
import datetime
import tempfile
from pathlib import Path
import unittest

from policy import strict_json, validate_database, validate_report, validate_sbom


class ImagePolicy(unittest.TestCase):
    def setUp(self):
        self.source = 'a'*40
        self.image = {'tag':'aegisai-api:fixture'}
        self.report = {'SchemaVersion':2,'ArtifactType':'container_image','Metadata':{
            'OS':{'Family':'alpine','Name':'3.24.4'},'RepoTags':[self.image['tag']],
            'ImageConfig':{'config':{'Labels':{'org.opencontainers.image.revision':self.source}}}},
            'Results':[{'Class':'os-pkgs','Packages':[{'Name':'fixture-os'}]},
                       {'Class':'lang-pkgs','Type':'node-pkg','Packages':[{'Name':'fixture-node'}]}]}

    def test_blocked_unfixed_and_unknown_vulnerabilities_are_never_waived(self):
        validate_report(self.report,self.image,self.source,'api')
        for severity in ('HIGH','CRITICAL','UNKNOWN','unexpected'):
            report = copy.deepcopy(self.report)
            report['Results'][0]['Vulnerabilities'] = [{'Severity':severity,'VulnerabilityID':'fixture','FixedVersion':''}]
            with self.assertRaises(ValueError):
                validate_report(report,self.image,self.source,'api')

    def test_wrong_image_source_eol_and_missing_package_coverage_fail_closed(self):
        for mutate in [lambda r:r['Metadata']['OS'].update(EOSL=True),
                       lambda r:r['Metadata'].update(RepoTags=['other-image']),
                       lambda r:r['Metadata']['ImageConfig']['config']['Labels'].clear(),
                       lambda r:r.update(Results=[]),
                       lambda r:r.update(Results=r['Results'][:1])]:
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.assertRaises((ValueError,KeyError)):
                validate_report(report,self.image,self.source,'api')

    def test_stale_database_and_incomplete_sbom_are_rejected(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        fresh = {'Version':2,'UpdatedAt':now.isoformat(),'DownloadedAt':now.isoformat()}
        validate_database(fresh,now)
        stale = dict(fresh,UpdatedAt=(now-datetime.timedelta(hours=49)).isoformat())
        with self.assertRaises(ValueError):
            validate_database(stale,now)
        for bom in ({'bomFormat':'CycloneDX','components':[]},
                    {'bomFormat':'other','components':[{}]},
                    {'bomFormat':'CycloneDX','components':[{'purl':'pkg:apk/alpine/fixture@1'}]}):
            with self.assertRaises(ValueError):
                validate_sbom(bom,'api')

    def test_duplicate_and_nonfinite_security_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'fixture.json'
            for value in ('{"approved":true,"approved":false}','{"severity":NaN}'):
                path.write_text(value)
                with self.assertRaises(ValueError):
                    strict_json(path)


if __name__ == '__main__':
    unittest.main()
