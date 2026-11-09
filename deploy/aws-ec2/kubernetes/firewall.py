"""Admit only local/self/pod access to the private Kubernetes control ports."""
import os
import subprocess

CHAIN = 'AEGISAI-K3S-IN'


def run(*args, check=True):
    return subprocess.run(['iptables', '-w', '10', *args], check=check,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    assert os.geteuid() == 0
    # Never flush global/foreign chains; this chain has a single explicit owner.
    if run('-nL', CHAIN, check=False).returncode:
        run('-N', CHAIN)
    rules = [('-i', 'lo', '-j', 'ACCEPT'),
             ('-s', '172.31.55.151/32', '-j', 'ACCEPT'),
             ('-s', '10.44.0.0/16', '-j', 'ACCEPT'), ('-j', 'DROP')]
    observed = subprocess.check_output(['iptables', '-S', CHAIN], text=True)
    if '-A ' + CHAIN not in observed:
        for rule in rules:
            run('-A', CHAIN, *rule)
    else:
        for rule in rules:
            assert run('-C', CHAIN, *rule, check=False).returncode == 0, 'FIREWALL_DRIFT'
        assert len(observed.splitlines()) == len(rules) + 1, 'EXTRA_FIREWALL_RULE'
    jump = ('-p', 'tcp', '-m', 'multiport', '--dports', '6443,10250', '-j', CHAIN)
    if run('-C', 'INPUT', *jump, check=False).returncode:
        run('-I', 'INPUT', '1', *jump)


if __name__ == '__main__':
    main()
