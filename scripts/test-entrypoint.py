#!/usr/bin/env python3
"""Check route policy before any file, interface or daemon operation."""
import os
from pathlib import Path
import subprocess
import unittest


class RoutePolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (Path(__file__).resolve().parent.parent / 'deploy/entrypoint.sh').read_text()
        cls.guard = source.split('test -r /config/wg0.conf\n', 1)[0] + '\nexit 0\n'
        assert cls.guard != source + '\nexit 0\n'

    def check(self, routes, address='10.77.0.1/32'):
        return subprocess.run(
            ['sh', '-c', self.guard], capture_output=True,
            env={**os.environ, 'TUNNEL_ADDRESS': address, 'TUNNEL_ROUTES': routes},
        ).returncode

    def test_entire_phone_allocation_pool_and_existing_destinations(self):
        for host in range(1, 255):
            with self.subTest(host=host):
                self.assertEqual(self.check(f'10.77.0.{host}/32'), 0)
        self.assertEqual(self.check('10.77.0.2/32 10.77.0.3/32 10.77.0.253/32 10.77.0.254/32'), 0)

    def test_broad_outside_noncanonical_and_shell_syntax_rejected(self):
        for route in ('0.0.0.0/0', '::/0', '10.77.0.0/24', '10.77.0.1/31',
                      '10.77.0.0/32', '10.77.0.255/32', '10.77.0.256/32',
                      '10.77.0.999/32', '10.77.1.3/32', '192.168.0.3/32',
                      '10.77.0.03/32', '10.77.0.+3/32', '10.77.0.3',
                      '10.77.0.*/32', '10.77.0.3/32;true', '$(true)'):
            with self.subTest(route=route):
                self.assertEqual(self.check(route), 2)
                self.assertEqual(self.check('10.77.0.3/32 ' + route), 2)

    def test_missing_routes_and_unapproved_interface_addresses_rejected(self):
        self.assertNotEqual(self.check(''), 0)
        self.assertNotEqual(self.check('10.77.0.3/32', '10.77.0.99/32'), 0)
        self.assertEqual(self.check('10.77.0.1/32', '10.77.0.254/32'), 0)


if __name__ == '__main__':
    unittest.main()
