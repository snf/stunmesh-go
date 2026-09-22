#!/usr/bin/env python3
"""Run local builds/tests without host credentials or signing keys.

STUNMESH_BUILD_ROOT points at the private tool/cache/artifact workspace.
Network is disabled unless --network is explicitly used to fetch pinned inputs.
"""
import argparse
import os
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--network', action='store_true')
p.add_argument('--write-source', action='store_true')
p.add_argument('--repo', choices=('go', 'android'), default='go')
p.add_argument('--net-admin', action='store_true')
p.add_argument('command', nargs=argparse.REMAINDER)
a = p.parse_args()
if a.network and a.net_admin:
    p.error('test network capabilities require an isolated network')
workspace = Path(__file__).resolve().parents[2]
build = Path(os.environ.get('STUNMESH_BUILD_ROOT', workspace / 'stunmesh-build')).resolve()
source = workspace / ('stunmesh-' + a.repo)
for folder in ('cache', 'work', 'artifacts', 'tools'):
    (build / folder).mkdir(parents=True, exist_ok=True)
cmd = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv']
if a.network:
    cmd += ['--share-net']
if a.net_admin:
    cmd += ['--uid', '0', '--gid', '0', '--cap-add', 'CAP_NET_ADMIN', '--cap-add', 'CAP_NET_RAW']
cmd += ['--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--dev', '/dev', '--dir', '/proc', '--tmpfs', '/tmp', '--dir', '/etc']
for path in ('/etc/ssl/certs', '/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf', '/etc/ld.so.cache', '/etc/alternatives', '/proc/cpuinfo', '/proc/meminfo', '/proc/stat'):
    if Path(path).exists():
        cmd += ['--ro-bind', path, path]
cmd += ['--ro-bind', str(build / 'tools'), '/tools', '--bind', str(build / 'cache'), '/cache',
        '--bind', str(build / 'work'), '/work', '--bind', str(build / 'artifacts'), '/artifacts',
        '--bind' if a.write_source else '--ro-bind', str(source), '/src', '--chdir', '/src']
env = {
    'PATH': '/tools/go/bin:/tools/jdk/bin:/cache/gopath/bin:/usr/bin:/bin',
    'LANG': 'C.UTF-8', 'TZ': 'UTC', 'GOTOOLCHAIN': 'local', 'GOTELEMETRY': 'off',
    'GOROOT': '/tools/go', 'GOPATH': '/cache/gopath', 'GOCACHE': '/cache/go', 'GOMAXPROCS': '4',
    'GOFLAGS': '-mod=readonly', 'GOPROXY': 'https://proxy.golang.org' if a.network else 'off',
    'GOSUMDB': 'sum.golang.org', 'GRADLE_USER_HOME': '/cache/gradle',
    'JAVA_HOME': '/tools/jdk', 'JAVA_TOOL_OPTIONS': '-Duser.home=/work/java-user',
    'ANDROID_HOME': '/tools/android-sdk', 'ANDROID_SDK_ROOT': '/tools/android-sdk',
    'ANDROID_NDK_HOME': '/tools/android-sdk/ndk/29.0.14206865',
    'ANDROID_USER_HOME': '/work/android-user', 'XDG_CACHE_HOME': '/cache/xdg',
}
for key, value in env.items():
    cmd += ['--setenv', key, value]
command = a.command
if command and command[0] == '--':
    command = command[1:]
if not command:
    p.error('a command is required')
os.execvp('bwrap', cmd + command)
