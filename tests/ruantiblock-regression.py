#!/usr/bin/env python3
"""Run real ucode/fs against temporary fixtures; never touch router configuration.

Usage: python3 tests/ruantiblock-regression.py --ucode /usr/bin/ucode --real-uci
With --real-uci the interpreter needs fs.so and uci.so. Without it a fixture
module supplies committed UCI data and only fs.so is required.
Production paths/imports are replaced in a temporary copy, never in the plugin.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

PLUGIN = Path(__file__).resolve().parents[1] / 'root/usr/share/rpcd/ucode/dns-monitor-ruantiblock'
PARSER = argparse.ArgumentParser()
PARSER.add_argument('--ucode', default=os.environ.get('UCODE', 'ucode'))
PARSER.add_argument('--real-uci', action='store_true', help='Exercise actual libuci parsing too')
OPTIONS, UNITTEST_ARGS = PARSER.parse_known_args()


class RuantiblockSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='dns-monitor-ruantiblock-')
        self.root = Path(self.temp.name)
        self.etc = self.root / 'etc'
        self.rb = self.etc / 'ruantiblock'
        self.lists = self.rb / 'user_lists'
        self.uci = self.etc / 'config'
        self.lists.mkdir(parents=True)
        self.uci.mkdir()
        self.binary = self.root / 'ruantiblock'
        self.binary.write_text(f'#!/bin/sh\nprintf invoked > \"{self.root / "executed"}\"\nexit 99\n')
        self.binary.chmod(0o755)
        self.conf = self.rb / 'ruantiblock.conf'
        self.conf.write_text('DATA_DIR="/var/ruantiblock"\nUSER_INSTANCES_MAX=5\n')
        self.uci_file = self.uci / 'ruantiblock'
        self.uci_file.write_text("config user_instance 'list1'\n option u_enabled '1'\n option u_proxy_mode '2'\n")
        self.sections = {
            'list1': {'.type': 'user_instance', '.anonymous': False, 'u_enabled': '1', 'u_proxy_mode': '2', 'u_if_vpn': 'tun0'},
            'list2': {'.type': 'user_instance', '.anonymous': False, 'u_enabled': '0', 'u_proxy_mode': '2', 'u_if_vpn': 'wg0'},
            'list3': {'.type': 'user_instance', '.anonymous': False, 'u_enabled': '1', 'u_proxy_mode': '1'},
            'list4': {'.type': 'main', 'u_enabled': '1', 'u_proxy_mode': '2'},
            'arbitrary': {'.type': 'user_instance', 'u_enabled': '1', 'u_proxy_mode': '2'},
        }
        for n in range(1, 6):
            (self.lists / f'list{n}').write_text('')
        self.target = self.lists / 'list1'
        self.fixture_json = self.root / 'sections.json'
        self.fault_file = self.root / 'fault'
        self.fault_file.write_text('')
        self.driver = self.root / 'driver.uc'
        self.plugin = self.root / 'plugin.uc'
        source = PLUGIN.read_text()
        replacements = {
            "import * as fs from 'fs';": "import * as fs from './fixture-fs.uc';",
            "import { cursor } from 'uci';": "import { cursor } from './fixture-uci.uc';",
            "const ROOT_DIR = '/etc/ruantiblock';": f'const ROOT_DIR = {json.dumps(str(self.rb))};',
            "const UCI_DIR = '/etc/config';": f'const UCI_DIR = {json.dumps(str(self.uci))};',
            "const BINARY = '/usr/bin/ruantiblock';": f'const BINARY = {json.dumps(str(self.binary))};',
            'const TRUSTED_UID = 0;': f'const TRUSTED_UID = {os.getuid()};',
            "['/etc', ROOT_DIR, LIST_DIR, UCI_DIR]": f'[{json.dumps(str(self.etc))}, ROOT_DIR, LIST_DIR, UCI_DIR]',
        }
        if OPTIONS.real_uci:
            del replacements["import { cursor } from 'uci';"]
        for old, new in replacements.items():
            self.assertEqual(source.count(old), 1, f'Fixture replacement is unambiguous: {old}')
            source = source.replace(old, new)
        self.plugin.write_text(source)
        (self.root / 'fixture-uci.uc').write_text(
            "import { readfile } from 'fs';\n"
            "export function cursor() {\n"
            f" let sections = json(readfile({json.dumps(str(self.fixture_json))}));\n"
            " return { load: function() { return true; }, get_all: function(pkg, id) { return sections[id]; } };\n};\n")
        self.create_fs_fixture()
        self.driver.write_text(
            "import { readfile } from 'fs';\n"
            f"let methods = loadfile({json.dumps(str(self.plugin))}, {{ raw_mode: true }})();\n"
            "let input = json(readfile(ARGV[0]));\n"
            "print(sprintf('%J', methods['dns-monitor.ruantiblock'][input.method].call({args: input.args})), '\\n');\n")

    def tearDown(self):
        self.temp.cleanup()

    def create_fs_fixture(self):
        path = json.dumps(str(self.target))
        fault = json.dumps(str(self.fault_file))
        lines = ["import * as real from 'fs';", f"function fault() {{ return real.readfile({fault}); }}",
                 "function temporary(path) { return index(path, '/.dns-monitor-') >= 0 && substr(path, -4) == '.tmp'; }"]
        for name in ['error', 'lstat', 'stat', 'opendir', 'readlink', 'chmod', 'unlink']:
            lines.append(f'export const {name} = real.{name};')
        lines.extend([
            "export function open(path, mode, perm) {",
            " if (fault() == 'open' && mode == 'wxe' && temporary(path)) return null;",
            " let fd = real.open(path, mode, perm);",
            " if (!fd) return null;",
            " return {",
            "  fileno: function() { return fd.fileno(); },",
            "  lock: function(op) { return fault() == 'lock' ? null : fd.lock(op); },",
            "  read: function(n) { return fault() == 'read' && substr(path, -6) == '/list1' ? null : fd.read(n); },",
            "  write: function(data) { return fault() == 'write' && temporary(path) ? null : fd.write(data); },",
            "  close: function() { let result = fd.close(); return fault() == 'close' && temporary(path) ? null : result; }",
            " };",
            "};",
            "export function chown(path, uid, gid) {",
            " if (fault() == 'chown') return null;",
            " let result = real.chown(path, uid, gid);",
            f" if (fault() == 'external-edit') {{ let fd = real.open({path}, 'w'); fd.write('#new\\n'); fd.close(); }}",
            f" if (fault() == 'external-replace') {{ let fd = real.open({path} + '.other', 'w'); fd.write('#new\\n'); fd.close(); real.rename({path} + '.other', {path}); }}",
            f" if (fault() == 'config-edit') {{ let fd = real.open({json.dumps(str(self.conf))}, 'a'); fd.write('USER_LISTS_DIR=\"/custom\"\\n'); fd.close(); }}",
            f" if (fault() == 'uci-edit') {{ let fd = real.open({json.dumps(str(self.uci_file))}, 'a'); fd.write('#external\\n'); fd.close(); }}",
            " return result;",
            "};",
            "export function rename(oldpath, newpath) { return fault() == 'rename' ? null : real.rename(oldpath, newpath); };",
        ])
        (self.root / 'fixture-fs.uc').write_text('\n'.join(lines) + '\n')

    def rpc(self, method='add', domains=None, list_id='list1', fault=''):
        self.fixture_json.write_text(json.dumps(self.sections))
        if OPTIONS.real_uci:
            lines = []
            for name, section in self.sections.items():
                section_name = '' if section.get('.anonymous') else f" '{name}'"
                lines.append(f"config {section['.type']}{section_name}")
                for key, value in section.items():
                    if not key.startswith('.'):
                        lines.append(f" option {key} '{value}'")
            self.uci_file.write_text('\n'.join(lines) + '\n')
        self.fault_file.write_text(fault)
        request = self.root / 'request.json'
        request.write_text(json.dumps({'method': method, 'args': {} if method == 'lists' else {
            'list': list_id, 'domains': ['example.com'] if domains is None else domains}}))
        command = [OPTIONS.ucode, str(self.driver), str(request)]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse((self.root / 'executed').exists(), 'No automatic ruantiblock apply command')
        return json.loads(completed.stdout)

    def assert_rejected(self, **kwargs):
        before = self.target.read_bytes() if self.target.is_file() else None
        result = self.rpc(**kwargs)
        self.assertTrue(result.get('error'), result)
        self.assertEqual(result['added'], 0)
        self.assertFalse(result['pending'])
        if before is not None:
            self.assertEqual(self.target.read_bytes(), before)
        self.assertEqual(list(self.lists.glob('.dns-monitor-*')), [], 'Atomic replacement fixtures cleaned')
        return result

    def test_exact_discovery_schema_and_selection(self):
        result = self.rpc(method='lists')
        self.assertEqual(set(result), {'available', 'lists'})
        self.assertTrue(result['available'])
        self.assertEqual([entry['id'] for entry in result['lists']], ['list1', 'list2', 'list3'])
        self.assertEqual(result['lists'][0], {'id': 'list1', 'name': 'list1', 'enabled': True, 'interface': 'tun0', 'mode': 'vpn'})
        self.assertFalse(result['lists'][1]['enabled'])
        self.assertFalse(result['lists'][2]['enabled'])

    def test_append_preserves_every_byte_override_comment_and_permissions(self):
        original = b'# Comment\r\nExample.COM 8.8.8.8#53\r\n192.0.2.1\nlegacy_entry'
        self.target.write_bytes(original)
        self.target.chmod(0o640)
        before = self.target.stat()
        result = self.rpc(domains=['EXAMPLE.com.', 'New.Example.ORG.', 'new.example.org', 'xn--e1afmkfd.xn--p1ai'])
        self.assertEqual(set(result), {'added', 'duplicates', 'pending', 'message'})
        self.assertEqual((result['added'], result['duplicates'], result['pending']), (2, 2, True))
        self.assertEqual(self.target.read_bytes(), original + b'\nnew.example.org\nxn--e1afmkfd.xn--p1ai\n')
        after = self.target.stat()
        self.assertEqual((after.st_mode & 0o7777, after.st_uid, after.st_gid), (0o640, before.st_uid, before.st_gid))
        self.assertIn('/usr/bin/ruantiblock update', result['message'])
        self.assertIn('restart DNS', result['message'])
        self.assertIn('not applied', result['message'])
        self.assertTrue((self.lists / '.dns-monitor.lock').is_file())

    def test_duplicate_only_does_not_replace_or_apply(self):
        self.target.write_text('example.com 1.1.1.1\n')
        inode = self.target.stat().st_ino
        result = self.rpc(domains=['EXAMPLE.COM.', 'example.com'])
        self.assertEqual((result['added'], result['duplicates'], result['pending']), (0, 2, False))
        self.assertEqual(self.target.stat().st_ino, inode)

    def test_invalid_domains_fail_entire_batch(self):
        invalid = ['http://example.com', '*.example.com', 'a_b.example', '192.0.2.1', '2001:db8::1',
                   '-a.example', 'a-.example', 'a..example', ' example.com', 'example.com\n',
                   'example.com..', 'example.123', 'localhost', 'é.example', 'a' * 64 + '.com',
                   '.'.join(['a' * 63] * 4) + '.com', '', None, 7, 'example.xn--']
        for value in invalid:
            with self.subTest(value=value):
                self.assert_rejected(domains=['valid.example', value])

    def test_domain_and_batch_bounds(self):
        longest = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 61])
        self.assertEqual(len(longest), 253)
        self.assertEqual(self.rpc(domains=[longest])['added'], 1)
        self.assert_rejected(domains=[])
        self.assert_rejected(domains=['x.example'] * 501)
        self.assert_rejected(domains='example.com')
        self.assertEqual(self.rpc(domains=[f'd{n}.example' for n in range(500)])['added'], 500)

    def test_arbitrary_ids_and_ineligible_sections(self):
        for value in ['../list1', '/etc/passwd', 'list6', 'arbitrary', 'list2', 'list3', 'list4', None, 1]:
            with self.subTest(value=value):
                self.assert_rejected(list_id=value)
        self.sections['list1']['.anonymous'] = True
        self.assert_rejected()

    def test_missing_optional_installation(self):
        self.binary.unlink()
        result = self.rpc(method='lists')
        self.assertFalse(result['available'])
        self.assertEqual(result['lists'], [])
        self.assertTrue(result['error'])
        self.assert_rejected()

    def test_custom_config_and_shell_logic_are_never_executed(self):
        configs = ['USER_LISTS_DIR="/custom"', "USER_LISTS_DIR='${CONFIG_DIR}/user_lists'",
                   'USER_LISTS_DIR="/etc/ruantiblock/user_lists/../user_lists"',
                   'USER_LISTS_DIR="$(touch /tmp/unsafe)"', 'CONFIG_DIR="/custom"',
                   'NAME="custom"', '. /tmp/custom', 'if true; then USER_LISTS_DIR=/custom; fi',
                   'DATA_DIR="/var/ruantiblock"; USER_LISTS_DIR=/custom', 'eval "$OVERRIDE"']
        for config in configs:
            with self.subTest(config=config):
                self.conf.write_text(config + '\n')
                self.assert_rejected()
                self.assertFalse(self.rpc(method='lists')['available'])

    def test_literal_default_config_paths_supported(self):
        for config in [f'USER_LISTS_DIR="{self.lists}"',
                       f'CONFIG_DIR="{self.rb}"\nexport USER_LISTS_DIR="${{CONFIG_DIR}}/user_lists"']:
            with self.subTest(config=config):
                self.conf.write_text(config + '\n')
                self.assertTrue(self.rpc(method='lists')['available'])

    def test_symlink_and_hardlink_targets_rejected(self):
        other = self.root / 'other'
        other.write_text('untouched\n')
        self.target.unlink()
        self.target.symlink_to(other)
        self.assert_rejected()
        self.assertFalse(self.rpc(method='lists')['lists'][0]['enabled'])
        self.target.unlink()
        os.link(other, self.target)
        self.assert_rejected()
        self.assertEqual(other.read_text(), 'untouched\n')

    def test_symlink_config_and_directory_rejected(self):
        saved_conf = self.root / 'saved-conf'
        self.conf.rename(saved_conf)
        self.conf.symlink_to(saved_conf)
        self.assert_rejected()
        self.conf.unlink()
        saved_conf.rename(self.conf)
        saved_lists = self.root / 'saved-lists'
        self.lists.rename(saved_lists)
        self.lists.symlink_to(saved_lists, target_is_directory=True)
        self.assert_rejected()

    def test_unsafe_permissions_and_oversize_list(self):
        for object_path in [self.lists, self.target, self.conf, self.uci_file]:
            with self.subTest(path=object_path):
                old_mode = object_path.stat().st_mode & 0o7777
                object_path.chmod(old_mode | 0o020)
                self.assert_rejected()
                object_path.chmod(old_mode)
        self.target.write_bytes(b'#' * (1048576 + 1))
        self.assert_rejected()
        self.target.write_bytes(b'#' * 1048576)
        self.assert_rejected(domains=['new.example'])

    def test_fifo_is_rejected_without_blocking(self):
        self.target.unlink()
        os.mkfifo(self.target)
        self.assert_rejected()

    def test_lock_contention_and_stale_persistent_lock(self):
        lock = self.lists / '.dns-monitor.lock'
        with lock.open('w+') as handle:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_rejected()
        self.assertEqual(self.rpc()['added'], 1, 'Unlocked persistent inode is reusable after crash')

    def test_symlink_lock_rejected(self):
        other = self.root / 'other-lock'
        other.write_text('untouched')
        (self.lists / '.dns-monitor.lock').symlink_to(other)
        self.assert_rejected()
        self.assertEqual(other.read_text(), 'untouched')

    def test_external_updates_not_overwritten(self):
        for fault in ['external-edit', 'external-replace']:
            with self.subTest(fault=fault):
                self.target.write_text('#old\n')
                result = self.rpc(fault=fault)
                self.assertTrue(result.get('error'), result)
                self.assertEqual(result['added'], 0)
                self.assertFalse(result['pending'])
                self.assertEqual(self.target.read_text(), '#new\n')
                self.assertEqual(list(self.lists.glob('.dns-monitor-*')), [])

    def test_configuration_updates_abort_save(self):
        for fault in ['config-edit', 'uci-edit']:
            with self.subTest(fault=fault):
                self.conf.write_text('DATA_DIR="/var/ruantiblock"\n')
                self.assert_rejected(fault=fault)

    def test_io_failure_paths_are_useful_and_preserve_original(self):
        self.target.write_text('# original\n')
        for fault in ['open', 'read', 'write', 'close', 'chown', 'rename', 'lock']:
            with self.subTest(fault=fault):
                result = self.assert_rejected(fault=fault)
                self.assertGreater(len(result['error']), 15)


if __name__ == '__main__':
    unittest.main(argv=[__file__, *UNITTEST_ARGS])
