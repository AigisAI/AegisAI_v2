"""Real Helm schema rejection and render, not text-only manifest assertions."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser();parser.add_argument('helm',type=Path);args=parser.parse_args()
    chart=Path(__file__).with_name('chart')
    values={'images':{'api':'docker.io/library/aegisai-api@sha256:'+'a'*64,
                     'web':'docker.io/library/aegisai-web@sha256:'+'b'*64},
            'revision':'c'*40,'apiReplicas':1,'frontendIngressCidrs':['172.18.0.4/32','172.29.240.2/32']}
    with tempfile.TemporaryDirectory() as temporary:
        path=Path(temporary)/'values.json';path.write_text(json.dumps(values))
        base=[str(args.helm),'template','aegisai-private',str(chart),'-n','aegisai-private','-f',str(path)]
        subprocess.run([str(args.helm),'lint',str(chart),'--strict','-f',str(path)],check=True)
        result=subprocess.run(base,capture_output=True,text=True,check=True)
        assert len(result.stdout)<128*1024
        for option in ('images.api=aegisai-api:mutable','apiReplicas=3','frontendIngressCidrs[0]=0.0.0.0/0'):
            rejected=subprocess.run(base+['--set',option],capture_output=True,text=True)
            assert rejected.returncode!=0 and 'schema' in rejected.stderr.lower(),option
    print(json.dumps({'helmRender':'passed','actualSchemaRejects':['mutable-image','excess-replicas','public-ingress']}))


if __name__=='__main__':main()
