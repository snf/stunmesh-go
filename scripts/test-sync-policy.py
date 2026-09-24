#!/usr/bin/env python3
"""VPN-only transport and extensible enrollment regression tests."""
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


def load(name,file):
    loader=importlib.machinery.SourceFileLoader(name,str(Path(__file__).with_name(file)))
    spec=importlib.util.spec_from_loader(name,loader)
    module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module


admin=load('sync_admin_test','syncthing-admin')
service=load('sync_service_test','syncthing-service')


def device(letter): return '-'.join([letter*7]*8)  # Syntax fixtures, not native identities.


def inventory():
    return {'devices':{'nas':device('A'),'laptop':device('B'),'phone':device('C')},
            'folders':{'shared':{'path':'/data/shared','type':'sendreceive','devices':['nas','laptop','phone']}}}


def root():
    return ET.fromstring('<configuration><gui><user>operator</user><password>$2a$fixture</password></gui><options><listenAddress>default</listenAddress></options></configuration>')


class SyncPolicy(unittest.TestCase):
    def test_fourth_device_needs_only_explicit_inventory_change(self):
        plan=inventory();tree=admin.pair(root(),'nas',device('A'),plan)
        folder=tree.find('folder');ET.SubElement(folder,'versioning',{'type':'staggered'})
        plan['devices']['future-phone']=device('D')
        # New peers get no folder automatically.
        tree=admin.pair(tree,'nas',device('A'),plan)
        self.assertEqual(len(tree.findall('device')),4)
        self.assertNotIn(device('D'),[d.get('id') for d in tree.findall('folder/device')])
        plan['folders']['shared']['devices'].append('future-phone')
        tree=admin.pair(tree,'nas',device('A'),plan)
        self.assertIn(device('D'),[d.get('id') for d in tree.findall('folder/device')])
        self.assertEqual(tree.find('folder/versioning').get('type'),'staggered')
        self.assertEqual(tree.findtext('folder/paused'),'true')

    def test_invalid_inventory_and_identity_are_rejected(self):
        for mutate in (
            lambda p:p['devices'].update(phone=device('A')),
            lambda p:p['folders']['shared'].update(devices=['nas','unknown']),
            lambda p:p['folders']['shared'].update(path='/data/../secret'),
            lambda p:p['folders'].update(nested={'path':'/data/shared/child','type':'sendreceive','devices':['nas','phone']}),
            lambda p:p['folders']['shared'].update(type='unsupported'),
        ):
            plan=inventory();mutate(plan)
            with self.assertRaises(RuntimeError):admin.inventory(plan,'nas')
        with self.assertRaises(RuntimeError):admin.pair(root(),'nas',device('D'),inventory())
        with self.assertRaises(RuntimeError):admin.inventory(inventory(),'laptop')

    def test_clients_only_dial_nas_vpn_address(self):
        plan=inventory();del plan['devices']['phone'];plan['folders']['shared']['devices']=['nas','laptop']
        tree=admin.pair(root(),'laptop',device('B'),plan)
        remote=next(d for d in tree.findall('device') if d.get('id')==device('A'))
        self.assertEqual(remote.findtext('address'),'tcp://10.77.0.1:22000')
        self.assertEqual(remote.findtext('allowedNetwork'),'10.77.0.0/24')
        self.assertEqual(tree.findtext('options/listenAddress'),'')
        for flag in ('globalAnnounceEnabled','localAnnounceEnabled','relaysEnabled','natEnabled'):
            self.assertEqual(tree.findtext('options/'+flag),'false')

    def test_server_passive_and_listener_exact(self):
        tree=admin.pair(root(),'nas',device('A'),inventory())
        admin.harden(tree,listen_address='tcp://10.77.0.1:22000')
        self.assertEqual(tree.findtext('options/listenAddress'),'tcp://10.77.0.1:22000')
        self.assertTrue(all(d.findtext('address')=='dynamic' for d in tree.findall('device')))
        self.assertEqual(tree.findtext('options/globalAnnounceEnabled'),'false')
        self.assertEqual(tree.findtext('options/localAnnounceEnabled'),'false')

    def test_runtime_joins_vpn_without_publishing_ports(self):
        settings={'vpn_container':'owned-vpn','role':'nas','mounts':{}}
        commands=[]
        def run(args,*rest):
            commands.append(args)
            if '{{.State.Running}}' in args:return b'true\n'
            if '{{.HostConfig.NetworkMode}}' in args:return b'pasta\n'
            if args[:2]==['podman','exec']:return b'wg0\n'
            return b''
        with patch.object(service.sys,'argv',['syncthing-service','start','--manifest','/fixture']),patch.object(service.os,'geteuid',return_value=1000),patch.object(Path,'read_text',return_value=json.dumps(settings)),patch.object(service,'validate',return_value=(Path('/cfg'),Path('/state'),root())),patch.object(service.admin,'args_for',return_value=[]),patch.object(service.admin,'save'),patch.object(service,'run',side_effect=run):
            service.main()
        launch=next(c for c in commands if c[:2]==['podman','run'])
        self.assertIn('--network=container:owned-vpn',launch)
        self.assertNotIn('-p',launch)
        self.assertIn('--log-driver=none',launch)
        self.assertNotIn('--privileged',launch)

    def test_volume_still_required_for_new_device_paths(self):
        import nas_common
        expected={'mountpoint':'/data','source':'/dev/mapper/data','fstype':'xfs','uuid':'correct'}
        actual={'filesystems':[{'target':'/data','source':'/dev/mapper/data','fstype':'xfs','uuid':'wrong'}]}
        with patch.object(Path,'read_text',return_value=json.dumps(expected)),patch.object(Path,'resolve',return_value=Path('/data')),patch.object(nas_common,'run',return_value=json.dumps(actual)):
            with self.assertRaises(RuntimeError):nas_common.volume_guard('/volume.json',['/data/backups/future-phone'])

    def test_client_refuses_underlay_route_before_launch(self):
        settings={'vpn_container':'owned-vpn','role':'laptop','mounts':{}}
        commands=[]
        def run(args,*rest):
            commands.append(args)
            if '{{.State.Running}}' in args:return b'true\n'
            if '{{.HostConfig.NetworkMode}}' in args:return b'pasta\n'
            if args[-2:]==['show','interfaces']:return b'wg0\n'
            if args[-2:]==['get','10.77.0.1']:return b'10.77.0.1 via 192.0.2.1 dev eth0\n'
            return b''
        with patch.object(service.sys,'argv',['syncthing-service','start','--manifest','/fixture']),patch.object(service.os,'geteuid',return_value=1000),patch.object(Path,'read_text',return_value=json.dumps(settings)),patch.object(service,'validate',return_value=(Path('/cfg'),Path('/state'),root())),patch.object(service.admin,'args_for',return_value=[]),patch.object(service.admin,'save') as save,patch.object(service,'run',side_effect=run):
            with self.assertRaisesRegex(RuntimeError,'not routed through WireGuard'):service.main()
            save.assert_not_called()
        self.assertFalse(any(c[:2]==['podman','run'] for c in commands))
        self.assertTrue(any('unreachable' in c and '10.77.0.1/32' in c for c in commands))


if __name__=='__main__':unittest.main()
