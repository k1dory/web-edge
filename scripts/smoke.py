#!/usr/bin/env python3
"""Exercise the real image against a mock backend, on an isolated Docker network."""
import argparse
import hashlib
import html
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import uuid

parser = argparse.ArgumentParser()
parser.add_argument('--image', default='web-edge:dev')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
prefix = 'web-edge-test-' + uuid.uuid4().hex[:10]
network, volume, backend, container = [prefix + suffix for suffix in ('-net', '-data', '-backend', '-edge')]
created = []


def docker(*cmd, check=True):
    p = subprocess.run(['docker', *cmd], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    if check and p.returncode:
        raise RuntimeError('docker ' + cmd[0] + ': ' + p.stdout[-6000:])
    return p.stdout.strip()


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    print('PASS', label, flush=True)


backend_code = '''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
class Handler(BaseHTTPRequestHandler):
    def handle_request(self):
        left = int(self.headers.get('Content-Length', '0')); size = left
        while left:
            b = self.rfile.read(min(left, 65536))
            if not b: break
            left -= len(b)
        b = json.dumps({'headers':dict(self.headers), 'path':self.path, 'size':size-left}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    do_GET = do_POST = handle_request
    def log_message(self,*args): pass
ThreadingHTTPServer(('0.0.0.0',8088), Handler).serve_forever()
'''


def healthy():
    for _ in range(60):
        state = json.loads(docker('inspect', container))[0]['State']
        if state.get('Health', {}).get('Status') == 'healthy':
            return
        time.sleep(1)
    raise RuntimeError('container not healthy: ' + docker('logs', '--tail', '25', container))


try:
    # All pulls happen before creating the network. Runtime has no Internet route.
    docker('image', 'inspect', args.image)
    if 'Error' in docker('image', 'inspect', 'python:3.12-alpine', check=False):
        docker('pull', 'python:3.12-alpine')
    docker('network', 'create', '--internal', network)
    created.append(('network', network))
    docker('volume', 'create', volume)
    created.append(('volume', volume))
    with tempfile.TemporaryDirectory(prefix=prefix) as tmp:
        tmp = Path(tmp); tmp.chmod(0o755)
        c = json.loads((root / 'examples/config.json').read_text())
        c['zone'], c['tls'] = 'gw.example.test', 'internal'
        c['identity'] = {'node':'smoke-host', 'host_ip':'10.20.0.5', 'container':'web-edge-smoke'}
        base = dict(c['sites'][0], name='app', profile='web', share_only=False, bot_check=False,
                    upstream='http://backend:8088', insecure_upstream_tls=False)
        c['sites'] = [base, dict(base, name='protected', bot_check=True),
                      dict(base, name='share', profile='qnap-share', share_only=True),
                      dict(base, name='login'), dict(base, name='small', max_body_mib=1)]
        config = tmp / 'config.json'; config.write_text(json.dumps(c)); config.chmod(0o644)
        docker('run', '-d', '--name', backend, '--network', network, '--network-alias', 'backend',
               '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
               '--pids-limit', '64', '--memory', '128m', 'python:3.12-alpine', 'python3', '-u', '-c', backend_code)
        created.append(('container', backend))
        docker('run', '-d', '--name', container, '--network', network, '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--pids-limit', '256', '--memory', '2g', '--cpus', '2',
               '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,uid=10001,gid=10001',
               '--mount', f'type=volume,src={volume},dst=/data',
               '--mount', f'type=bind,src={config},dst=/config/config.json,readonly',
               '-p', '127.0.0.1::8443', '-p', '127.0.0.1::8080', args.image)
        created.append(('container', container))
        healthy()
        state = json.loads(docker('inspect', container))[0]
        port = int(state['NetworkSettings']['Ports']['8443/tcp'][0]['HostPort'])
        http_port = int(state['NetworkSettings']['Ports']['8080/tcp'][0]['HostPort'])
        conn = http.client.HTTPConnection('127.0.0.1', http_port, timeout=10)
        conn.request('GET', '/test?x=1', headers={'Host':'app.gw.example.test'})
        response = conn.getresponse()
        check('HTTP redirects to public HTTPS port', response.status == 308
              and response.getheader('Location') == 'https://app.gw.example.test/test?x=1')
        response.read(); conn.close()
        ca = docker('exec', container, '/usr/bin/web-edge', 'export', 'ca')
        tls = ssl.create_default_context(cadata=ca)

        def request(name, path='/', method='GET', body=None, headers=None):
            host = name + '.gw.example.test'
            conn = http.client.HTTPSConnection(host, port, context=tls, timeout=20)
            conn._create_connection = lambda *_a, **_kw: socket.create_connection(('127.0.0.1', port), timeout=20)
            hdr = {'User-Agent':'Mozilla/5.0 web-edge-smoke', 'Host':host, 'Accept':'*/*'}
            hdr.update(headers or {})
            conn.request(method, path, body=body, headers=hdr)
            r = conn.getresponse(); h = dict(r.getheaders()); h['_cookies'] = r.headers.get_all('Set-Cookie', [])
            result = r.status, h, r.read(); conn.close(); return result

        status, _, data = request('app', '/headers', headers={'X-Forwarded-For':'203.0.113.1', 'X-Real-IP':'203.0.113.2', 'Forwarded':'for=203.0.113.3'})
        hdr = {k.lower():v for k,v in json.loads(data)['headers'].items()}
        source_ip = hdr['x-real-ip']
        check('TLS trusted, upstream reachable, forged headers replaced', status == 200
              and hdr['x-forwarded-for'] == source_ip and source_ip not in ['203.0.113.1','203.0.113.2'] and 'forwarded' not in hdr)
        for path in ['/?q=%27%20OR%201%3D1--', '/?q=%3Cscript%3Ealert(1)%3C/script%3E', '/?file=/etc/passwd']:
            check('WAF blocks ' + path, request('app', path)[0] == 403)
        for path in ['/', '/cgi-bin/', '/cgi-bin/login.html', '/cgi-bin/authLogin.cgi', '/share.cgi', '/share.cgi?', '/login?next=/share.cgi?x=1']:
            check('share-only rejects ' + path, request('share', path)[0] == 404)
        check('share endpoint allowed with query', request('share', '/share.cgi?ssid=fixture')[0] == 200)
        asset = '/cgi-bin/apps/fileManager/js/shlkPlugin.js'
        check('sharing asset allowed', request('share', asset)[0] == 200)
        check('POST to sharing asset rejected', request('share', asset, 'POST', b'')[0] == 404)
        form = b'user=fixture&pwd=ZHVtbXk%3D'
        for _ in range(20):
            assert request('login', '/cgi-bin/authLogin.cgi', 'POST', form, {'Content-Type':'application/x-www-form-urlencoded'})[0] == 200
        status, hdr, _ = request('login', '/cgi-bin/authLogin.cgi')
        check('login limit returns 429 and Retry-After', status == 429 and 'Retry-After' in hdr)
        check('request body limit enforced', request('small', '/upload', 'POST', b'x'*(2*1024*1024), {'Content-Type':'text/plain'})[0] == 413)
        multipart = b'--fixture\r\nContent-Disposition: form-data; name="file"; filename="test.bin"\r\nContent-Type: application/octet-stream\r\n\r\n' + b'x'*(16*1024*1024) + b'\r\n--fixture--\r\n'
        status, _, data = request('app', '/upload', 'POST', multipart, {'Content-Type':'multipart/form-data; boundary=fixture'})
        check('16 MiB upload intact', status == 200 and json.loads(data)['size'] == len(multipart))
        del multipart
        status, hdr, _ = request('protected')
        check('protected site redirects to Anubis', status == 307 and 'botcheck.gw.example.test' in hdr['Location'])
        dest = urllib.parse.urlsplit(hdr['Location'])
        challenge_path = dest.path + '?' + dest.query
        check('declared headless browser denied', request('botcheck', challenge_path, headers={'User-Agent':'HeadlessChrome/156.0'})[0] == 403)
        status, hdr, data = request('botcheck', challenge_path)
        check('normal browser gets challenge', status == 200 and b'anubis_challenge' in data)
        challenge = json.loads(html.unescape(re.search(rb'<script[^>]*id="anubis_challenge"[^>]*>(.*?)</script>', data, re.S).group(1).decode()))['challenge']
        cookies = '; '.join(s.split(';',1)[0] for s in hdr['_cookies'])
        start = time.monotonic()
        for nonce in range(2_000_000):
            digest = hashlib.sha256((challenge['randomData'] + str(nonce)).encode()).hexdigest()
            if digest.startswith('0000'): break
        else: raise RuntimeError('proof exceeded bounded work budget')
        query = urllib.parse.urlencode(dict(id=challenge['id'], response=digest, nonce=nonce,
            redir='https://protected.gw.example.test/', elapsedTime=max(1,int((time.monotonic()-start)*1000))))
        status, hdr, _ = request('botcheck', '/.within.website/x/cmd/anubis/api/pass-challenge?' + query, headers={'Cookie':cookies})
        check('PoW succeeds with Secure HttpOnly cookie', status == 302 and any('Secure' in s and 'HttpOnly' in s for s in hdr['_cookies']))
        cookies = '; '.join(s.split(';',1)[0] for s in hdr['_cookies'])
        check('valid proof reaches backend', request('protected', headers={'Cookie':cookies})[0] == 200)
        docker('restart', container); healthy()
        check('cookie and certificate survive restart', request('protected', headers={'Cookie':cookies})[0] == 200)
        docker('exec', container, 'cscli', '-c', '/data/crowdsec/config.yaml', 'decisions', 'add', '--ip', source_ip, '--duration', '1m', '--reason', 'isolated-smoke')
        for _ in range(12):
            if request('app')[0] == 403: break
            time.sleep(1)
        else: raise AssertionError('CrowdSec decision not enforced')
        check('CrowdSec ban enforced by Caddy', True)
        docker('exec', container, 'cscli', '-c', '/data/crowdsec/config.yaml', 'decisions', 'delete', '--ip', source_ip)
        for _ in range(12):
            if request('app')[0] == 200: break
            time.sleep(1)
        else: raise AssertionError('CrowdSec decision not removed')
        records = []
        for line in docker('logs', container).splitlines():
            try: records.append(json.loads(line))
            except json.JSONDecodeError: pass
        waf = [r for r in records if 'Coraza:' in r.get('message','')]
        check('WAF logs retain host and container identity', bool(waf) and all(r.get('node')=='smoke-host' and r.get('host_ip')=='10.20.0.5' and r.get('container')=='web-edge-smoke' for r in waf))
        print('All isolated image checks passed', flush=True)
except Exception:
    if ('container', container) in created:
        print(docker('logs', '--tail', '25', container, check=False))
    raise
finally:
    for kind, name in reversed(created):
        if kind == 'container': docker('rm', '-f', name, check=False)
        elif kind == 'volume': docker('volume', 'rm', name, check=False)
        else: docker('network', 'rm', name, check=False)
