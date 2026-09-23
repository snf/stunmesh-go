#!/usr/bin/env python3
"""Configuration safety tests. No host mounts, network or cloud credentials."""
import importlib.machinery
import importlib.util
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

if __name__=='__main__': unittest.main()
