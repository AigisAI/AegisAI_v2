"""Install only the private broker; no consumer, ingress or repository activation."""
import grp
import os
import pathlib
import pwd
import shutil
import subprocess

assert os.geteuid()==0
os.umask(0o077)
root=pathlib.Path('/opt/aegisai')
release=(root/'shared/candidate-release').read_text().strip()
assert release.startswith('ec2-runtime-') and all(char.isalnum() or char=='-' for char in release)
source=pathlib.Path(__file__).resolve().parent

try:
    group=grp.getgrgid(50001)
    assert group.gr_name=='aegisai-fetch'
except KeyError:
    subprocess.run(['groupadd','--gid','50001','aegisai-fetch'],check=True)
try:
    user=pwd.getpwuid(50001)
    assert user.pw_name=='aegisai-fetch' and user.pw_gid==50001 and user.pw_shell=='/usr/sbin/nologin'
except KeyError:
    subprocess.run(['useradd','--system','--uid','50001','--gid','50001','--no-create-home',
        '--home-dir','/nonexistent','--shell','/usr/sbin/nologin','aegisai-fetch'],check=True)

subprocess.run(['python3',str(source/'prepare-managed-env.py')],check=True)
shutil.copyfile(source/'run-private-broker.sh',root/'operator/run-private-broker.sh')
(root/'operator/run-private-broker.sh').chmod(0o700)
shutil.copyfile(source/'aegisai-private-broker.service','/etc/systemd/system/aegisai-private-broker.service')
pathlib.Path('/etc/systemd/system/aegisai-private-broker.service').chmod(0o644)
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','enable','--now','aegisai-private-broker.service'],check=True)
print('PRIVATE_BROKER_INSTALLED_NO_CONSUMER_OR_INGRESS')
