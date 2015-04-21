import subprocess
import time
import sys
import os
import re

PYTHON_VERSION = sys.version_info[0]
CACHE = {}
CACHE_MAX_AGE = 60 * 60 * 48  # 48h

try:
    import json
except ImportError:
    import simplejson as json


def cache_load(cf):
    if not os.path.isfile(cf): return
    global CACHE
    f = open(cf, 'r')
    try:
        CACHE = json.load(f)
    except:
        pass
    f.close()


def cache_save(cf):
    global CACHE
    f = open(cf, 'w')
    json.dump(CACHE, f)
    f.close()


def do_query(dl, force=0, cache_file=None, slow_down=0, ignore_returncode=0, robust_query=0):
    k = '.'.join(dl)
    if cache_file: cache_load(cache_file)
    if force or k not in CACHE or CACHE[k][0] < time.time() - CACHE_MAX_AGE:
        CACHE[k] = (
        int(time.time()),
        _do_whois_query(k, ignore_returncode, robust_query),
        )
        if cache_file: cache_save(cache_file)
        if slow_down: time.sleep(slow_down)

    return CACHE[k][1]

def _do_whois_query(dq, ignore_returncode, robust_query):
    """
        Linux 'whois' command wrapper
    """
    if not type(dq) is list:
        dq = [dq]
    dq[:0] = ['whois']
    p = subprocess.Popen(dq, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    r = p.communicate()[0]
    if PYTHON_VERSION == 3:
        try:
            r = r.decode()
        except UnicodeDecodeError:
            r = r.decode('ISO-8859-1')

    if not ignore_returncode and p.returncode != 0: raise Exception(r)

    if robust_query:
        rq = re.findall(r'single out[^"]+"xxx"', r, re.IGNORECASE)
        if rq:
            # multiple records present, be more specific
            r = _do_whois_query(['domain {:s}'.format(dq[1])], ignore_returncode, robust_query)
        rq = re.findall(r'Invalid query', r, re.IGNORECASE)
        if rq:
            # Pass query to a specific referal server as indicated in previous response
            rq = re.findall(r'Whois Server:\s{0,}(.+)', r, re.IGNORECASE)
            try:
                dq = re.search(r'domain\s(.+)', dq[1], re.IGNORECASE).group(1)
            except AttributeError:
                raise Exception('Cannot find domain part!')
            r = _do_whois_query(['-h',rq[0],dq], ignore_returncode, robust_query)
    return r


"""
import socket

def _do_whois_query(dl):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((('%s.whois-servers.net' % dl[-1], 43)))
	s.send(("%s\r\n" % '.'.join(dl)).encode())

	response = []
	while 1:
		t = s.recv(4096)
		response.append(t)
		if t == b'': break

	s.close()
	return b''.join(response).decode()
"""
