#!/usr/bin/env python3
"""Configuration safety tests. No host mounts, network or cloud credentials."""
import importlib.machinery
import importlib.util
from contextlib import ExitStack
from types import SimpleNamespace
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

def load(name,file):
    loader=importlib.machinery.SourceFileLoader(name,str(Path(__file__).with_name(file)))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    mod=importlib.util.module_from_spec(spec);loader.exec_module(mod);return mod

admin=load('admin','syncthing-admin');backup=load('backup','backup-job')
startup=load('startup','start-services')
import nas_common

class Services(unittest.TestCase):
    def test_pauses_and_removes_public_discovery(self):
        root=ET.fromstring('<configuration><gui enabled="true"><user>operator</user><password>$2a$test-fixture</password><address>0.0.0.0:8384</address></gui><options><listenAddress>default</listenAddress><listenAddress>quic://0.0.0.0:22000</listenAddress></options><folder id="default"/><folder id="keep"/><device introducer="true"><autoAcceptFolders>true</autoAcceptFolders></device></configuration>')
        admin.harden(root)
        self.assertEqual(root.find('gui').get('enabled'),'false')
        self.assertEqual(root.findtext('device/autoAcceptFolders'),'false')
        self.assertEqual(root.findtext('device/paused'),'true')
        self.assertEqual(root.findtext('folder/paused'),'true')
        self.assertEqual(len(root.findall('folder')),1)
        self.assertEqual([n.text for n in root.findall('options/listenAddress')],['tcp://0.0.0.0:22000'])
        for option in ('globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled','crashReportingEnabled'):
            self.assertEqual(root.findtext('options/'+option),'false')
        self.assertEqual(root.find('folder').get('rescanIntervalS'),'3600')
        self.assertEqual(root.findtext('options/autoUpgradeIntervalH'),'0')
    def test_gui_requires_native_password_hash(self):
        for password in ('','plaintext'):
            root=ET.fromstring('<configuration><gui><user>operator</user><password>'+password+'</password></gui><options/></configuration>')
            with self.assertRaises(RuntimeError): admin.harden(root,True)
    def test_backup_disabled_before_mount_or_cloud_calls(self):
        with patch.object(backup,'volume_guard',side_effect=AssertionError('must not reach mounts')):
            with self.assertRaisesRegex(RuntimeError,'disabled'): backup.validate({'enabled':False})
        worker=Path(__file__).resolve().parents[1]/'deploy/restic/worker.sh'
        p=subprocess.run(['sh',str(worker)],env={'PATH':'/usr/bin:/bin'},capture_output=True)
        self.assertEqual(p.returncode,78)
        self.assertIn(b'disabled',p.stderr)
    def test_wrong_volume_rejected(self):
        expected={'mountpoint':'/srv/data','source':'/dev/mapper/ciphered','fstype':'xfs','uuid':'expected'}
        actual={'filesystems':[{'target':'/srv/data','source':'/dev/mapper/ciphered','fstype':'xfs','uuid':'other'}]}
        with patch.object(Path,'read_text',return_value=json.dumps(expected)),patch.object(Path,'resolve',return_value=Path('/srv/data')),patch.object(nas_common,'run',return_value=json.dumps(actual)):
            with self.assertRaisesRegex(RuntimeError,'not mounted'): nas_common.volume_guard('/fixture',['/srv/data/state'])

    def startup_context(self,argv=(),approved=False,running=b'',quota_error=None,volume_error=None):
        stack=ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(startup.sys,'argv',['start-services',*argv]))
        stack.enter_context(patch.object(startup.os,'geteuid',return_value=1000))
        stack.enter_context(patch.object(startup,'volume_guard',side_effect=volume_error))
        stack.enter_context(patch.object(Path,'stat',return_value=SimpleNamespace(st_dev=1,st_ino=2)))
        stack.enter_context(patch.object(Path,'read_text',return_value=json.dumps({'approved':approved})))
        quota=stack.enter_context(patch.object(startup,'key_capacity',side_effect=quota_error))
        calls=stack.enter_context(patch.object(startup,'run',return_value=running))
        return quota,calls

    def test_startup_refuses_missing_volume_or_quota_before_commands(self):
        for failure in ('volume','quota'):
            with self.subTest(failure=failure):
                quota,calls=self.startup_context(
                    quota_error=nas_common.KeyQuotaError('low') if failure=='quota' else None,
                    volume_error=RuntimeError('missing mount') if failure=='volume' else None)
                with self.assertRaises(RuntimeError): startup.main()
                calls.assert_not_called()
                self.doCleanups()

    def test_startup_check_cannot_start_services(self):
        _,calls=self.startup_context(argv=['--check'],approved=True)
        startup.main()
        self.assertEqual([c.args[0][:2] for c in calls.call_args_list],
                         [['podman','ps'],['/srv/containers/service-tools/syncthing-service','check']])

    def test_startup_does_not_touch_running_sync_or_start_disabled_jobs(self):
        for approved in (False,True):
            with self.subTest(approved=approved):
                quota,calls=self.startup_context(approved=approved,running=b'syncthing-v2\n' if approved else b'')
                startup.main()
                commands=[c.args[0] for c in calls.call_args_list]
                self.assertEqual([c[0] for c in commands],['podman','podman','podman-compose','podman'])
                self.assertEqual(quota.call_count,2)
                self.assertTrue(all('--force-recreate' not in c for c in commands))
                self.doCleanups()

    def test_startup_rechecks_quota_before_vpn_group(self):
        quota,calls=self.startup_context()
        quota.side_effect=[None,nas_common.KeyQuotaError('low')]
        with self.assertRaises(nas_common.KeyQuotaError): startup.main()
        self.assertEqual([c.args[0][:2] for c in calls.call_args_list],[['podman','ps'],['podman','compose']])

    def test_both_compose_forms_bounded_and_failure_output_withheld(self):
        for command in (['podman','compose','up','-d'],['podman-compose','up','-d']):
            with patch.object(nas_common.subprocess,'run',return_value=SimpleNamespace(returncode=124,stdout=b'secret-canary',stderr=b'secret-canary')) as execute:
                with self.assertRaises(RuntimeError) as error: nas_common.run(command)
            self.assertEqual(execute.call_args.args[0],['timeout','--kill-after=5s','90s',*command])
            self.assertNotIn('secret-canary',str(error.exception))

if __name__=='__main__': unittest.main()
