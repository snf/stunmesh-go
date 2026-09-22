#!/usr/bin/env python3
"""Run the kernel/proxy integration test in the image's isolated rootfs/netns.

Requires rootless user/network namespaces with NET_ADMIN and kernel WireGuard.
No host network, configuration, source checkout or signer is mounted.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--image', type=Path, required=True)
p.add_argument('--test-binary', type=Path, required=True)
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='image-test-') as work:
    layout, root = Path(work) / 'oci', Path(work) / 'rootfs'
    layout.mkdir(); root.mkdir()
    with tarfile.open(a.image) as tar:
        tar.extractall(layout, filter='data')
    def read(digest):
        algorithm, value = digest.split(':')
        if algorithm != 'sha256' or len(value) != 64:
            raise ValueError('unsupported OCI digest')
        data = (layout / 'blobs/sha256' / value).read_bytes()
        if hashlib.sha256(data).hexdigest() != value:
            raise ValueError('OCI checksum mismatch')
        return data
    index = json.loads((layout / 'index.json').read_text())
    manifest = json.loads(read(index['manifests'][0]['digest']))
    read(manifest['config']['digest'])
    for layer in manifest['layers']:
        with tarfile.open(fileobj=io.BytesIO(read(layer['digest']))) as tar:
            tar.extractall(root, filter='data')
    files = sorted(str(f.relative_to(root)) for f in root.rglob('*') if f.is_file())
    if files != ['bin/busybox', 'entrypoint.sh', 'lib/ld-musl-x86_64.so.1',
                 'usr/local/bin/stunmesh-go', 'usr/local/bin/wg']:
        raise ValueError('unexpected image files')
    for directory in ('dev', 'proc', 'tmp', 'run'):
        (root / directory).mkdir(exist_ok=True)
    command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--uid', '0', '--gid', '0', '--cap-add', 'CAP_NET_ADMIN', '--clearenv',
               '--ro-bind', str(root), '/', '--dev', '/dev', '--dir', '/proc',
               '--tmpfs', '/tmp', '--tmpfs', '/run',
               '--ro-bind', str(a.test_binary.resolve()), '/tmp/kernel.test',
               '--setenv', 'PATH', '/usr/local/bin:/bin', '--setenv', 'GOMAXPROCS', '2',
               '--setenv', 'STUNMESH_KERNEL_TEST', 'isolated-image',
               '/tmp/kernel.test', '-test.v', '-test.timeout=30s']
    result = subprocess.run(command)
    raise SystemExit(result.returncode)
