#!/usr/bin/env python3
"""Exercise the packaged CLI on a disposable GitHub-hosted Linux runner."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--cli', required=True)
parser.add_argument('--image', default='web-edge:dev')
args = parser.parse_args()
if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
    raise SystemExit('This test requires a disposable GitHub-hosted runner, not a workstation.')


def command(*argv, check=True):
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    if check and result.returncode:
        raise RuntimeError('command failed: ' + result.stdout[-6000:])
    return result


def docker(*argv, **kwargs):
    return command('docker', *argv, **kwargs)


docker('info')
if docker('container', 'ls', '-a', '--filter', 'name=^/web-edge$', '--format', '{{.ID}}').stdout.strip():
    raise SystemExit('Refusing to replace an existing web-edge container')
if docker('volume', 'ls', '--filter', 'name=^web-edge-data$', '--format', '{{.Name}}').stdout.strip():
    raise SystemExit('Refusing to reuse an existing web-edge-data volume')

try:
    with tempfile.TemporaryDirectory(prefix='web-edge-cli-') as directory:
        config = Path(directory) / 'config.json'

        def cli(*argv, check=True):
            return command(args.cli, *argv, '--config', str(config), check=check)

        cli('setup', '--zone', 'gw.example.test', '--email', 'ops@example.test', '--tls', 'internal',
            '--node', 'cli-host', '--host-ip', '10.20.0.5', '--name', 'nas',
            '--upstream', 'http://backend.example.test:8080', '--profile', 'qnap-share', '--no-start')
        # Includes the real offline Caddy config validation and first volume init.
        cli('up', '--image', args.image)
        state = json.loads(docker('inspect', 'web-edge').stdout)[0]
        assert state['State']['Health']['Status'] == 'healthy'
        assert state['Config']['User'] == '10001:10001'
        assert state['HostConfig']['ReadonlyRootfs']
        print('PASS packaged CLI first start, offline validation and health', flush=True)

        before = state['Id']
        assert cli('edit', 'nas', '--upstream', 'http://invalid host', check=False).returncode != 0
        assert json.loads(docker('inspect', 'web-edge').stdout)[0]['Id'] == before
        print('PASS invalid config preserves running container', flush=True)

        cli('add', '--name', 'docs', '--upstream', 'http://docs.example.test:8080')
        assert len(json.loads(config.read_text())['sites']) == 2
        state = json.loads(docker('inspect', 'web-edge').stdout)[0]
        assert state['Config']['Image'] == args.image
        cli('remove', 'docs')
        assert len(json.loads(config.read_text())['sites']) == 1
        cli('down')
        assert not json.loads(docker('inspect', 'web-edge').stdout)[0]['State']['Running']
        print('PASS packaged CLI add/remove/stop preserve selected image and state', flush=True)
finally:
    # Both names were verified absent before this test created them.
    docker('rm', '-f', 'web-edge', check=False)
    docker('volume', 'rm', 'web-edge-data', check=False)
