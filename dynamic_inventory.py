#!/usr/bin/python

### parsing a raw host list and filtering host_groups based on regular expresssions

import argparse
import subprocess
import re
import json
import sys


redis_hosts = []
redis_a_hosts = []
redis_b_hosts = []


def parse_args():
    parser = argparse.ArgumentParser(description="inventory script for Security Patching")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list', action='store_true')
    #group.add_argument('--host')
    return parser.parse_args()

def list_patching_hosts():
    cmd = "/usr/bin/cat rawhostlist"
    P = subprocess.check_output(cmd.split())

    for line in P.split():
        r1 = re.match("(\w+redis\d\d)", line)
        r2 = re.match("(\w+redis\d\da$)", line)
        r3 = re.match("(\w+redis\d\db$)", line)


        if r1:
            L1 = list(r1.groups())
            S1 = ''.join(str(e) for e in L1)
            redis_hosts.append(S1)
        if r2:
            L2 = list(r2.group())
            S2 = ''.join(str(f) for f in L2)
            redis_a_hosts.append(S2)
        if r3:
            L3 = list(r3.group())
            S3 = ''.join(str(g) for g in L3)
            redis_b_hosts.append(S3)
    return redis_hosts, redis_a_hosts, redis_b_hosts

def main():
    args = parse_args()
    if args.list:
        hosts = list_patching_hosts()
        json.dump({'redis': redis_hosts, 'redis_a': redis_a_hosts, 'redis_b': redis_b_hosts}, sys.stdout)

if __name__ == '__main__':
    main()
