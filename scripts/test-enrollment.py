#!/usr/bin/env python3
"""Offline enrollment wrapper regression tests; no live credentials or Podman."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

loader=importlib.machinery.SourceFileLoader('enroll',str(Path(__file__).with_name('stunmesh-enroll')))
spec=importlib.util.spec_from_loader(loader.name,loader)
enroll=importlib.util.module_from_spec(spec);loader.exec_module(enroll)

class Enrollment(unittest.TestCase):
    def test_secret_renderer_requires_terminal_before_any_work(self):
        with patch.object(enroll.os,'geteuid',return_value=1000),patch.object(enroll.sys,'argv',['stunmesh-enroll','phone','--qr']),patch.object(enroll.sys.stdout,'isatty',return_value=False),patch.object(enroll,'run') as command:
            with self.assertRaisesRegex(RuntimeError,'terminal'):enroll.main()
            command.assert_not_called()
    def test_unsafe_device_names_refused_before_any_work(self):
        for name in ('../peer','a/b','-x','phone\nsecret','x'*33):
            with patch.object(enroll.os,'geteuid',return_value=1000),patch.object(enroll.sys,'argv',['stunmesh-enroll',name]),patch.object(enroll,'run') as command:
                with self.assertRaises((RuntimeError,SystemExit)):enroll.main()
                command.assert_not_called()
    def test_private_files_reject_symlink_or_group_read(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'profile';p.write_text('{}');p.chmod(0o600)
            enroll.private(p)
            link=Path(directory)/'link';link.symlink_to(p)
            with self.assertRaises(RuntimeError):enroll.private(link)
            p.chmod(0o640)
            with self.assertRaises(RuntimeError):enroll.private(p)
    def test_pending_reservations_skip_only_hidden_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'.gitignore').write_text('derived QR')
            (root/'.enroll-incomplete').mkdir()
            child=root/'phone';child.mkdir(mode=0o700)
            file=child/'enrollment.json';file.write_text(json.dumps({'address':'10.77.0.3/32'}));file.chmod(0o600)
            self.assertEqual(enroll.reservations(root),['10.77.0.3/32'])
            file.write_text(json.dumps({'address':'10.77.0.0/24'}))
            with self.assertRaises(RuntimeError):enroll.reservations(root)
    def test_issuance_and_display_container_boundaries(self):
        settings={'image':'sha256:'+'0'*64,'server_config':'/fixture/config'}
        with patch.object(enroll,'mount_argument',side_effect=lambda src,dst,readonly=False:f'{src}:{dst}:{readonly}'),patch.object(enroll,'run',return_value=b'') as command:
            enroll.container(settings,['server-new'],config=True,output=Path('/fixture/output'))
            args=command.call_args.args[0]
            for flag in ('--network=none','--read-only','--log-driver=none','--cap-drop=all','--timeout=60'):self.assertIn(flag,args)
            self.assertIn('/fixture/config:/config:True',args)
            enroll.container(settings,['-t','ANSIUTF8'],render=Path('/fixture/phone'))
            args=command.call_args.args[0]
            self.assertNotIn('/fixture/config:/config:True',args)
            self.assertIn('/fixture/phone:/enrollment:True',args)

if __name__=='__main__':unittest.main()
