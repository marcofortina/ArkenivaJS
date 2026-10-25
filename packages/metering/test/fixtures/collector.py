# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Disposable integration collector; never deploy as an application service."""

import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-only', action='store_true', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--storage', required=True)
    args = parser.parse_args()
    credential = os.environ.get('ARKENIVAJS_METER_COLLECTOR_AUTHORIZATION', '')
    if not credential.startswith('Bearer ') or len(credential) < 20:
        raise SystemExit('A dedicated disposable collector credential is required')
    path = Path(args.storage).resolve()
    if path.parent.stat().st_mode & 0o022:
        raise SystemExit('Collector storage must use an owner-controlled directory')
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    seen = set()
    for line in path.read_text().splitlines():
        seen.add(json.loads(line)['eventId'])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_arguments):
            pass

        def do_GET(self):
            self.send_response(200 if self.path == '/readyz' else 404)
            self.end_headers()

        def do_POST(self):
            supplied = self.headers.get('Authorization', '')
            if not hmac.compare_digest(supplied.encode(), credential.encode()):
                self.send_error(401, 'Authentication required')
                return
            if self.path != '/v1/metering/events':
                self.send_error(404, 'Unknown collector route')
                return
            if self.headers.get('X-ArkenivaJS-Metering-Version') != '1.0.0':
                self.send_error(400, 'Unsupported protocol version')
                return
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if size < 1 or size > 16_777_216:
                    raise ValueError('Invalid batch size')
                batch = json.loads(self.rfile.read(size))
                if batch.get('schemaVersion') != '1.0.0':
                    raise ValueError('Unsupported event version')
                events = batch['events']
                if not isinstance(events, list) or not 1 <= len(events) <= 1000:
                    raise ValueError('Invalid event collection')
                pending = {}
                for event in events:
                    if event['schemaVersion'] != '1.0.0' or not isinstance(event['eventId'], str):
                        raise ValueError('Invalid event identity')
                    encoded = (json.dumps(event, allow_nan=False, separators=(',', ':')) + '\n').encode()
                    if len(encoded) > 16_385:
                        raise ValueError('Oversized event')
                    if event['eventId'] not in seen:
                        pending[event['eventId']] = encoded
            except (ValueError, KeyError, TypeError):
                self.send_error(400, 'Invalid event batch')
                return
            try:
                for encoded in pending.values():
                    position = 0
                    while position < len(encoded):
                        written = os.write(fd, encoded[position:])
                        if written == 0:
                            raise OSError('No storage progress')
                        position += written
                os.fsync(fd)
                seen.update(pending)
            except OSError:
                self.send_error(503, 'Collector storage unavailable')
                return
            self.send_response(202)
            self.send_header('Content-Length', '0')
            self.end_headers()

    server = HTTPServer((args.host, args.port), Handler)
    print('Disposable metering collector is ready', flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        os.close(fd)


if __name__ == '__main__':
    main()
