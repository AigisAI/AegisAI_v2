"""Atomic rules limited to dedicated UID 50001. Never flush host firewall tables.
GitHub /meta is public; this updater uses no application/SCM/AWS credential.
"""
import datetime
import fcntl
import ipaddress
import json
import os
import pathlib
import subprocess
import urllib.request

TABLE='aegisai_fetch'
assert os.geteuid()==0
os.umask(0o077)
root=pathlib.Path('/opt/aegisai/operator/fetch-egress')
root.mkdir(mode=0o700,exist_ok=True)
assert root.resolve()==root and root.stat().st_uid==0 and not root.stat().st_mode & 0o077
lock=(root/'update.lock').open('a')
fcntl.flock(lock,fcntl.LOCK_EX)
exists=subprocess.run(['nft','list','table','inet',TABLE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
if not exists:
    # No fetch process may run before its allow-list exists; all other users and
    # existing host firewall rules are untouched.
    deny=f'add table inet {TABLE}\nadd chain inet {TABLE} output {{ type filter hook output priority -10; policy accept; }}\nadd rule inet {TABLE} output meta skuid 50001 reject\n'
    subprocess.run(['nft','-f','-'],input=deny,text=True,check=True,capture_output=True)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args): return None

request=urllib.request.Request('https://api.github.com/meta',headers={
    'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10','User-Agent':'AegisAI-Egress-Updater'})
with urllib.request.build_opener(NoRedirect()).open(request,timeout=20) as response:
    assert response.status==200
    raw=response.read(262145)
assert len(raw)<=262144
api=json.loads(raw)['api']
assert isinstance(api,list) and 0<len(api)<=256
networks=[]
for value in api:
    assert isinstance(value,str) and len(value)<=80
    network=ipaddress.ip_network(value,strict=True)
    assert network.network_address.is_global and network.broadcast_address.is_global
    assert network.prefixlen >= (8 if network.version==4 else 16)
    networks.append(network)
v4=list(ipaddress.collapse_addresses(network for network in networks if network.version==4))
v6=list(ipaddress.collapse_addresses(network for network in networks if network.version==6))
assert v4
rules=[f'delete table inet {TABLE}',f'add table inet {TABLE}',
    f'add chain inet {TABLE} output {{ type filter hook output priority -10; policy accept; }}']
for family,version,entries in [('ipv4_addr',4,v4),('ipv6_addr',6,v6)]:
    rules.append(f'add set inet {TABLE} github_api_v{version} {{ type {family}; flags interval; }}')
    if entries: rules.append(f'add element inet {TABLE} github_api_v{version} {{ '+', '.join(map(str,entries))+' }')
rules += [
    f'add rule inet {TABLE} output meta skuid 50001 ct state established,related accept',
    f'add rule inet {TABLE} output meta skuid 50001 ip daddr 127.0.0.53 udp dport 53 accept',
    f'add rule inet {TABLE} output meta skuid 50001 ip daddr 127.0.0.53 tcp dport 53 accept',
    f'add rule inet {TABLE} output meta skuid 50001 ip daddr @github_api_v4 tcp dport 443 accept',
    f'add rule inet {TABLE} output meta skuid 50001 ip6 daddr @github_api_v6 tcp dport 443 accept',
    f'add rule inet {TABLE} output meta skuid 50001 counter reject with icmpx type admin-prohibited']
encoded='\n'.join(rules)+'\n'
subprocess.run(['nft','--check','-f','-'],input=encoded,text=True,check=True,capture_output=True)
subprocess.run(['nft','-f','-'],input=encoded,text=True,check=True,capture_output=True)
report={'updatedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'uid':50001,
    'apiIpv4Networks':len(v4),'apiIpv6Networks':len(v6),'source':'https://api.github.com/meta',
    'otherUsersAffected':False,'metadataAndHostAccess':'denied'}
pending=root/'current.pending.json';pending.write_text(json.dumps(report));pending.replace(root/'current.json')
print(json.dumps(report))
