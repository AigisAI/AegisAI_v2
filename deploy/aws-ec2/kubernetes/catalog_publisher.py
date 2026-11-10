"""Publish only validated non-secret host status; never refresh its timestamp."""
import datetime
import json
import os
from pathlib import Path
import re
import stat

from foundation import kube

SOURCE=Path('/opt/aegisai/scanner/catalog/current.json')


def bounded_status(value, now):
    assert isinstance(value,dict)
    assert type(value.get('ready')) is bool and type(value.get('busy')) is bool
    assert value.get('ai') == 'DISABLED'
    updated=datetime.datetime.fromisoformat(value['updatedAt'].replace('Z','+00:00'))
    assert updated.tzinfo is not None and -5 <= (now-updated).total_seconds() <= 60
    result={key:value[key] for key in ('ready','busy','ai','updatedAt')}
    if value['ready']:
        assert re.fullmatch('java-v1:[a-f0-9]{16}:[a-f0-9]{64}',value['scannerSetVersion'])
        assert value['policyVersion']=='private-java-v1'
        result.update(scannerSetVersion=value['scannerSetVersion'],policyVersion=value['policyVersion'])
    return result


def main():
    assert os.geteuid()==0 and __debug__
    os.umask(0o077)
    fd=os.open(SOURCE,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and info.st_size<=4096
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(4097)
        assert len(raw)<=4096
    finally:os.close(fd)
    value=bounded_status(json.loads(raw),datetime.datetime.now(datetime.timezone.utc))
    document={'apiVersion':'v1','kind':'ConfigMap','metadata':{
        'name':'runtime-catalog','namespace':'aegisai-private'},'data':{'current.json':json.dumps(value,separators=(',',':'))}}
    kube('--cache-dir=/run/aegisai-catalog-cache','apply','--server-side',
         '--field-manager=aegisai-catalog-publisher','-f','-',value=document)


if __name__=='__main__':
    main()
