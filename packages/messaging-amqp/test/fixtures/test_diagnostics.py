# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Verify startup diagnostic bounds, ownership and private value removal."""
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def test_output_limit_and_malformed_bytes(self):
        result = diagnostics.capture((sys.executable, '-c',
                                      'import os; os.write(1, b"\\xff" * 10000)'), limit=127)
        self.assertEqual(len(result['text']), 127)
        self.assertEqual(result['limit'], 'output-limit')
        self.assertEqual(set(result['text']), {'\ufffd'})

    def test_timeout_retires_an_inherited_pipe(self):
        started = time.monotonic()
        script = ('import subprocess, sys; child = subprocess.Popen('
                  '[sys.executable, "-c", "import time; time.sleep(30)"]); '
                  'print(child.pid, flush=True)')
        result = diagnostics.capture((sys.executable, '-c', script), timeout=0.1)
        self.assertEqual(result['limit'], 'timeout')
        self.assertLess(time.monotonic() - started, 2)
        child_status = Path('/proc') / result['text'].strip() / 'stat'
        deadline = time.monotonic() + 1
        while child_status.exists() and time.monotonic() < deadline:
            if child_status.read_text().split()[2] == 'Z':
                break
            time.sleep(0.01)
        if child_status.exists():
            self.assertEqual(child_status.read_text().split()[2], 'Z')

    def test_complete_output(self):
        result = diagnostics.capture((sys.executable, '-c', 'print("broker boot failed")'))
        self.assertEqual(result['text'], 'broker boot failed\n')
        self.assertIsNone(result['limit'])

    def test_foreign_container_refuses_logs(self):
        with tempfile.TemporaryDirectory(prefix='arkenivajs-amqp-') as root:
            output = io.StringIO()
            with patch.object(diagnostics, 'capture', return_value={'exitCode': 0, 'limit': None, 'text': 'foreign'}) as call:
                diagnostics.startup_failure(Path(root), Path(root).name, output)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(output.getvalue(), 'Owned AMQP startup diagnostics are unavailable\n')

    def test_exact_private_values_and_unknown_uri_credentials_are_redacted(self):
        with tempfile.TemporaryDirectory(prefix='arkenivajs-amqp-') as root:
            directory = Path(root)
            values = ['private-cookie-value', 'private-password-value', 'private-hash-value', 'private-user-value']
            private_body = 'inert-private-body-only-for-diagnostic-test'
            private_key = '\n'.join(['-----BEGIN ' + 'PRIVATE KEY-----', private_body,
                                     '-----END ' + 'PRIVATE KEY-----'])
            (directory / 'cookie').write_text(values[0])
            (directory / 'server.key').write_text(private_key)
            (directory / 'definitions.json').write_text(json.dumps({'users': [{'name': values[3], 'password_hash': values[2]}]}))
            (directory / 'runtime.json').write_text(json.dumps({'users': {'service': {'username': values[3], 'password': values[1]}}}))
            raw = '\n'.join(values + [private_key, private_body, 'amqps://unknown-user:unknown-password@localhost', 'BOOT FAILED'])
            results = [{'exitCode': 0, 'limit': None, 'text': 'amqp'},
                       {'exitCode': 0, 'limit': None, 'text': '{"ExitCode":1}'},
                       {'exitCode': 0, 'limit': None, 'text': raw}]
            output = io.StringIO()
            with patch.object(diagnostics, 'capture', side_effect=results):
                diagnostics.startup_failure(directory, directory.name, output)
            parsed = json.loads(output.getvalue())['amqpStartupDiagnostics']
            self.assertIn('BOOT FAILED', parsed['tail']['text'])
            for secret in values + [private_body, 'unknown-user', 'unknown-password']:
                self.assertNotIn(secret, output.getvalue())
            self.assertNotIn('\n', output.getvalue().rstrip('\n'))

    def test_missing_secret_inventory_refuses_raw_logs(self):
        with tempfile.TemporaryDirectory(prefix='arkenivajs-amqp-') as root:
            output = io.StringIO()
            with patch.object(diagnostics, 'capture', return_value={'exitCode': 0, 'limit': None, 'text': 'amqp'}) as call:
                diagnostics.startup_failure(Path(root), Path(root).name, output)
            self.assertEqual(call.call_count, 1)
            self.assertEqual(output.getvalue(), 'Owned AMQP startup diagnostics are unavailable\n')

    def test_truncated_private_value_is_not_emitted(self):
        with tempfile.TemporaryDirectory(prefix='arkenivajs-amqp-') as root:
            directory = Path(root)
            (directory / 'definitions.json').write_text('{"users": []}')
            results = [{'exitCode': 0, 'limit': None, 'text': 'amqp'},
                       {'exitCode': 0, 'limit': None, 'text': '{}'},
                       {'exitCode': -9, 'limit': 'output-limit',
                        'text': 'BOOT FAILED\namqps://private-incomplete-password'}]
            output = io.StringIO()
            with patch.object(diagnostics, 'capture', side_effect=results):
                diagnostics.startup_failure(directory, directory.name, output)
            self.assertNotIn('private-incomplete-password', output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['amqpStartupDiagnostics']['tail']['text'], 'BOOT FAILED')


if __name__ == '__main__':
    unittest.main()
