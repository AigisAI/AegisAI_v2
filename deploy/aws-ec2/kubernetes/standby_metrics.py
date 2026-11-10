"""Enable the independently labeled standby scrape, retaining the old API job."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from bootstrap import now


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    root=Path('/opt/aegisai/observability')
    path=root/'config/compose.json';original=json.loads(path.read_text())
    config=root/'config/prometheus.yaml';text=config.read_text()
    assert 'aegisai-api-kubernetes' not in text
    directory=root/'discovery'
    assert directory.is_dir() and not directory.is_symlink()
    targets=json.loads((directory/'private-api-targets.json').read_text())
    assert len(targets)==1 and targets[0]['labels']['runtime']=='kubernetes'
    backup=root/'config/pre-kubernetes-standby-metrics';assert not backup.exists()
    backup.mkdir(mode=0o700)
    for item in (path,config):shutil.copyfile(item,backup/item.name)
    volumes=original['services']['prometheus']['volumes']
    assert isinstance(volumes,list) and all('/etc/aegisai/discovery' not in str(v) for v in volumes)
    volumes.append(str(directory)+':/etc/aegisai/discovery:ro')
    path.write_text(json.dumps(original,indent=2))
    config.write_text(text+'''  - job_name: aegisai-api-kubernetes
    file_sd_configs:
      - files: ['/etc/aegisai/discovery/private-api-targets.json']
        refresh_interval: 15s
''')
    try:
        subprocess.run(['docker','compose','-f',str(path),'config','--quiet'],check=True,timeout=20)
        subprocess.run(['docker','exec','aegisai-observability-prometheus-1','/bin/promtool','check','config',
                        '/etc/aegisai/prometheus.yaml'],check=True,timeout=20)
        subprocess.run(['docker','compose','-f',str(path),'up','-d','--no-deps','prometheus'],check=True,timeout=90)
        subprocess.run(['systemctl','start','aegisai-data-bridge.service'],check=True,timeout=35)
    except Exception:
        for item in (path,config):shutil.copyfile(backup/item.name,item)
        subprocess.run(['docker','compose','-f',str(path),'up','-d','--no-deps','prometheus'],check=False,timeout=90)
        raise
    report={'standbyMetricsConfiguration':'installed','existingApiScrapePreserved':True,
            'prometheusInternetRouteAdded':False,'onlyPodCidrRouteAdded':True,
            'actualScrapeVerified':False,'trafficMoved':False,'installedAt':now()}
    (root/'standby-metrics-result.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report))


if __name__=='__main__':main()
