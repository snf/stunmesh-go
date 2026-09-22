#!/usr/bin/env python3
"""Assemble an allowlisted no-RUN Podman build context from verified local inputs.
The OCI source must be the pinned Alpine image pulled by the documented Skopeo
command. Every OCI content digest and both retained file hashes are checked.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile

root=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--artifacts',type=Path,required=True)
p.add_argument('--context',type=Path,required=True)
a=p.parse_args()
inputs=json.loads((root/'build/inputs.json').read_text())
layout=a.artifacts/'alpine-base'
def blob(digest):
    algorithm,value=digest.split(':')
    if algorithm!='sha256' or len(value)!=64:raise ValueError('unsupported digest')
    b=(layout/'blobs/sha256'/value).read_bytes()
    if hashlib.sha256(b).hexdigest()!=value:raise ValueError('OCI digest mismatch')
    return b
index=json.loads((layout/'index.json').read_bytes())
manifestDigest=index['manifests'][0]['digest']
if manifestDigest!=inputs['alpine_amd64_manifest']:raise SystemExit('unexpected Alpine architecture manifest')
manifest=json.loads(blob(manifestDigest));blob(manifest['config']['digest'])
retained={}
for layer in manifest['layers']:
    with tarfile.open(fileobj=io.BytesIO(blob(layer['digest']))) as t:
        for name in ('bin/busybox','lib/ld-musl-x86_64.so.1'):
            member=t.getmember(name)
            if not member.isfile():raise ValueError('unexpected tool entry type')
            retained[Path(name).name]=t.extractfile(member).read()
for name,data in retained.items():
    if hashlib.sha256(data).hexdigest()!=inputs['image_tools'][name]:raise SystemExit('image tool hash mismatch')
if a.context.exists() and any(a.context.iterdir()):raise SystemExit('choose an empty new context directory')
(a.context/'build/image').mkdir(parents=True,exist_ok=True)
(a.context/'deploy').mkdir()
for name,data in retained.items():(a.context/'build/image'/name).write_bytes(data)
for name in ('stunmesh-go','wg'):
    shutil.copyfile(a.artifacts/name,a.context/'build/image'/name)
for name in ('Dockerfile','.dockerignore','deploy/entrypoint.sh'):shutil.copyfile(root/name,a.context/name)
for path in (a.context/'build/image').iterdir():path.chmod(0o755)
report={str(path.relative_to(a.context)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(a.context.rglob('*')) if path.is_file()}
(a.artifacts/'image-context-sha256.json').write_text(json.dumps(report,indent=2)+'\n')
print('Prepared',len(report),'allowlisted files; no source tree, Git, keys or configuration copied')
