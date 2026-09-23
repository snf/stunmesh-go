"""Small deployment checks shared by the offline NAS service helpers."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

def run(args,data=None):
    p=subprocess.run(args,input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if p.returncode:
        raise RuntimeError('command failed: '+Path(args[0]).name+' '+args[1]+' (output withheld)')
    return p.stdout

def atomic(path,data):
    fd,name=tempfile.mkstemp(prefix='.service-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def mount_argument(source,target,readonly=False):
    source=Path(source).resolve(strict=True)
    if any(x in str(source) for x in ',\n:') or not target.startswith('/'):
        raise RuntimeError('unsafe bind path')
    return 'type=bind,src='+str(source)+',dst='+target+(',ro' if readonly else '')

def volume_guard(record,paths):
    """Check the exact mounted filesystem before even creating state directories."""
    expected=json.loads(Path(record).read_text())
    if set(expected)!={'mountpoint','source','fstype','uuid'} or not expected['uuid']:
        raise RuntimeError('record a complete expected volume identity')
    mountpoint=Path(expected['mountpoint'])
    if not mountpoint.is_absolute() or mountpoint.resolve()!=mountpoint:
        raise RuntimeError('volume mountpoint must be a canonical absolute path')
    info=json.loads(run(['findmnt','--json','--mountpoint',str(mountpoint),'-o','TARGET,SOURCE,FSTYPE,UUID']))['filesystems']
    if len(info)!=1 or any(info[0].get(k)!=expected[k] for k in ('source','fstype','uuid')) or info[0]['target']!=str(mountpoint):
        raise RuntimeError('required unlocked filesystem is not mounted')
    for value in paths:
        path=Path(value).resolve()
        if path==mountpoint or mountpoint not in path.parents:
            raise RuntimeError('service data must be below the verified large volume')
        while not path.exists(): path=path.parent
        actual=json.loads(run(['findmnt','--json','--target',str(path),'-o','UUID']))['filesystems']
        if len(actual)!=1 or actual[0].get('uuid')!=expected['uuid']:
            raise RuntimeError('source/state path resolves to another filesystem')

def inactive(paths):
    """Inspect only mount metadata, never container argv/environment."""
    names=run(['podman','ps','--format','{{.Names}}']).decode().splitlines()
    for name in names:
        mounts=json.loads(run(['podman','inspect','--format','{{json .Mounts}}',name]))
        for mount in mounts or []:
            source=Path(mount.get('Source','/nonexistent')).resolve()
            if any(source==p.resolve() or source in p.resolve().parents or p.resolve() in source.parents for p in paths):
                raise RuntimeError('a running container already uses this configuration/state')
