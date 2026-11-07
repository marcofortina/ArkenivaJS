# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Verify the actual AMQPS fixture chain under strict X.509 validation."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import control
from prepare import generate_certificates


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='arkeniva-amqp-certificates-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        generate_certificates(cls.root)

    def test_actual_fixture_chain_passes_strict_openssl_validation(self):
        result = subprocess.run(['openssl', 'verify', '-x509_strict', '-verify_hostname', 'localhost',
                                 '-CAfile', str(self.root / 'ca.crt'), str(self.root / 'server.crt')],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, 'The actual fixture chain must pass strict validation')

    def listener(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / 'server.crt', self.root / 'server.key')
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        errors = []

        def serve():
            try:
                with listener.accept()[0] as stream:
                    stream.settimeout(5)
                    with context.wrap_socket(stream, server_side=True):
                        pass
            except (OSError, ssl.SSLError) as error:
                errors.append(type(error).__name__)
            finally:
                listener.close()

        worker = threading.Thread(target=serve)
        worker.start()
        self.addCleanup(listener.close)
        self.addCleanup(lambda: worker.join(timeout=6))
        return port, worker, errors

    def test_actual_readiness_accepts_the_chain_with_strict_python_tls(self):
        factory = ssl.create_default_context
        contexts = []

        def strict_context(**kwargs):
            context = factory(**kwargs)
            context.verify_flags |= ssl.VERIFY_X509_STRICT
            contexts.append(context)
            return context

        port, worker, errors = self.listener()
        with patch.object(control.ssl, 'create_default_context', side_effect=strict_context):
            control.ready({'caFile': str(self.root / 'ca.crt'), 'port': port}, timeout=3)
        worker.join(timeout=6)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(contexts[0].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(contexts[0].check_hostname)
        self.assertTrue(contexts[0].verify_flags & ssl.VERIFY_X509_STRICT)

    def test_actual_strict_tls_still_rejects_a_foreign_hostname(self):
        port, worker, _ = self.listener()
        context = ssl.create_default_context(cafile=str(self.root / 'ca.crt'))
        context.verify_flags |= ssl.VERIFY_X509_STRICT
        with socket.create_connection(('127.0.0.1', port), timeout=3) as stream:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(stream, server_hostname='foreign.invalid')
        worker.join(timeout=6)
        self.assertFalse(worker.is_alive())

    def test_timeout_reports_only_safe_last_verification_evidence(self):
        failure = ssl.SSLCertVerificationError(1, 'The certificate was rejected')
        failure.verify_code = 92
        failure.verify_message = 'CA cert does not include key usage extension'
        value = {'caFile': str(self.root / 'ca.crt'), 'port': 1,
                 'users': {'service': {'password': 'inert-private-fixture-value'}}}
        with patch.object(control.time, 'monotonic', side_effect=[0, 0, 1]), \
                patch.object(control.time, 'sleep'), \
                patch.object(control.socket, 'create_connection', side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                control.ready(value, timeout=0.5)
        message = str(caught.exception)
        evidence = json.loads(message.split(': ', 1)[1])
        self.assertEqual(evidence['lastCertificateVerification'], {
            'verifyCode': 92, 'verifyMessage': failure.verify_message})
        self.assertEqual(evidence['openssl'], ssl.OPENSSL_VERSION)
        self.assertIsInstance(evidence['verifyFlags'], int)
        self.assertNotIn(value['users']['service']['password'], message)
        self.assertNotIn(str(self.root), message)
        self.assertNotIn('BEGIN CERTIFICATE', message)


if __name__ == '__main__':
    unittest.main()
