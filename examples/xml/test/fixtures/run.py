# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

"""Run native XML conformance in a disposable network namespace, then drop all root groups."""
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys


def main():
    if sys.argv[1:2] == ['--isolated']:
        if os.geteuid() != 0:
            raise SystemExit('The network namespace helper requires its controlled root entry')
        uid, gid = int(sys.argv[2]), int(sys.argv[3])
        if uid < 1 or gid < 1:
            raise SystemExit('XML conformance must execute as a non-root user')
        original_namespace = int(sys.argv[4])
        if os.stat('/proc/self/ns/net').st_ino == original_namespace or {name for _, name in socket.if_nameindex()} != {'lo'}:
            raise SystemExit('XML conformance requires a separate network namespace containing only loopback')
        path, command = sys.argv[5], sys.argv[6:]
        subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], check=True, capture_output=True)
        environment = {'PATH': path, 'HOME': pwd.getpwuid(uid).pw_dir, 'LANG': 'C.UTF-8',
                       'ARKENIVA_XML_DISPOSABLE': '1', 'ARKENIVA_XML_NS_ACTIVE': '1'}
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
        os.execvpe(command[0], command, environment)
    if os.environ.get('ARKENIVA_XML_DISPOSABLE') != '1' or os.geteuid() == 0:
        raise SystemExit('XML conformance requires an explicitly owned VM or disposable CI runner and a non-root caller')
    if sys.argv[1:2] != ['--'] or len(sys.argv) < 3:
        raise SystemExit('Use run.py -- COMMAND [ARGUMENT ...]')
    arguments = ['sudo', '-n', '/usr/bin/unshare', '--net', '--fork', '--', sys.executable,
                 str(Path(__file__).resolve()), '--isolated', str(os.getuid()), str(os.getgid()),
                 str(os.stat('/proc/self/ns/net').st_ino), os.environ['PATH'], *sys.argv[2:]]
    result = subprocess.run(arguments, check=False)
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
