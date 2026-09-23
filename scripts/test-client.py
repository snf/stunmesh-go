#!/usr/bin/env python3
"""Host configuration tests use fixtures only; never edit host configuration."""
import importlib.machinery
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import json

loader=importlib.machinery.SourceFileLoader('client',str(Path(__file__).with_name('vpn-client')))
spec=importlib.util.spec_from_loader(loader.name,loader)
client=importlib.util.module_from_spec(spec);loader.exec_module(client)
loader=importlib.machinery.SourceFileLoader('peer',str(Path(__file__).with_name('vpn-peer')))
spec=importlib.util.spec_from_loader(loader.name,loader)
peer=importlib.util.module_from_spec(spec);loader.exec_module(peer)

class Hosts(unittest.TestCase):
    info={'hostnames':{'nas':'10.77.0.1','home23':'10.77.0.23'},'lan_hostnames':{'nas-lan':'192.168.0.10','home23-lan':'192.168.0.12'}}
    def test_preserve_other_names_and_comments(self):
        text='127.0.0.1 localhost\n192.168.0.10 nas unrelated # keep\n::1 ip6-localhost\n'
        result=client.hosts_text(text,self.info)
        self.assertIn('192.168.0.10\tunrelated # keep',result)
        self.assertIn('10.77.0.1\tnas\n',result)
        self.assertIn('::1 ip6-localhost',result)
        self.assertIn('192.168.0.10\tnas-lan',result)
    def test_refuse_ambiguity_and_foreign_mapping(self):
        for text in ['192.168.0.10 nas\n::1 nas\n','203.0.113.1 nas\n',client.BEGIN+'\n']:
            with self.assertRaises(RuntimeError): client.hosts_text(text,self.info)
    def test_service_has_no_boot_activation_or_excess_capability(self):
        unit=client.unit()
        self.assertNotIn('[Install]',unit)
        self.assertIn('Network=host',unit)
        self.assertIn('AddCapability=NET_ADMIN',unit)
        self.assertNotIn('SYS_MODULE',unit)
        self.assertIn('linux-run',unit)
        self.assertNotIn('/entrypoint.sh',unit)
        self.assertIn('Before=network-pre.target',client.guard_unit())
    def test_guard_recognizes_numeric_and_named_protocol(self):
        for protocol in (186,'186','bgp'):
            calls=[]
            def execute(args):
                calls.append(args)
                return json.dumps([{'type':'unreachable','metric':42777,'protocol':protocol}]).encode()
            with patch.object(client,'run',side_effect=execute):
                client.guard_routes({'allowed_ips':['10.77.0.1/32']})
            self.assertEqual(len(calls),1)
    def test_provisioning_disables_container_log_retention(self):
        with patch.object(peer,'run',return_value=b'') as execute:
            peer.container(['linux-issue','/output/profile.json'],b'{}',output=Path('/private/temporary'))
        args=execute.call_args.args[0]
        self.assertIn('--log-driver=none',args)
        self.assertIn('type=bind,src=/private/temporary,dst=/output,rw',args)

if __name__=='__main__': unittest.main()
