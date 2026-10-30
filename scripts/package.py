#!/usr/bin/env python3
"""Build Linux CLI binaries and .deb packages without external Python dependencies."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--version', default='0.1.0')
parser.add_argument('--arch', choices=['amd64', 'arm64'])
args = parser.parse_args()
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?', args.version):
    parser.error('invalid version')
out = root / 'dist'
out.mkdir(exist_ok=True)


def archive(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        for name, data, mode in files:
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            info.uid = info.gid = 0
            info.uname = info.gname = 'root'
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def deb(members):
    buf = bytearray(b'!<arch>\n')
    for name, data in members:
        buf += f'{name + "/":<16}{0:<12}{0:<6}{0:<6}{"100644":<8}{len(data):<10}`\n'.encode()
        buf += data
        if len(data) % 2:
            buf += b'\n'
    return bytes(buf)


for arch in ([args.arch] if args.arch else ['amd64', 'arm64']):
    binary = out / f'web-edge-linux-{arch}'
    subprocess.run(['go', 'build', '-trimpath', '-ldflags', f'-s -w -X main.version={args.version} -X github.com/k1dory/web-edge/internal/edge.DefaultImage=web-edge:{args.version}',
                    '-o', str(binary), './cmd/web-edge'], cwd=root,
                   env=dict(os.environ, GOOS='linux', GOARCH=arch, CGO_ENABLED='0'), check=True)
    control = f'''Package: web-edge
Version: {args.version}
Architecture: {arch}
Maintainer: k1dory <noreply@users.noreply.github.com>
Section: web
Priority: optional
Depends: docker-ce-cli | docker.io
Homepage: https://github.com/k1dory/web-edge
Description: Setup CLI for a Caddy, WAF, Anubis and CrowdSec container
 Interactive setup and management of protected reverse proxy publications.
 Docker Engine is required. Run sudo web-edge setup after installation.
'''.encode()
    files = [('usr/bin/web-edge', binary.read_bytes(), 0o755),
             ('usr/share/doc/web-edge/README.md', (root / 'README.md').read_bytes(), 0o644),
             ('usr/share/doc/web-edge/copyright', (root / 'LICENSE').read_bytes(), 0o644),
             ('usr/share/doc/web-edge/config.example.json', (root / 'examples/config.json').read_bytes(), 0o644)]
    pkg = out / f'web-edge_{args.version}_{arch}.deb'
    pkg.write_bytes(deb([('debian-binary', b'2.0\n'), ('control.tar.gz', archive([('control', control, 0o644)])),
                        ('data.tar.gz', archive(files))]))
    print(pkg)
assets = sorted(p for p in out.iterdir() if p.name.endswith('.deb') or p.name.startswith('web-edge-linux-'))
(out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in assets))
