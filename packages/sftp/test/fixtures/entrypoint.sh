# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it>

set -eu
mkdir -p /run/sshd /home/transfer/data/readonly
cp /fixture/user.pub /run/authorized.keys
chown transfer:transfer /run/authorized.keys /home/transfer /home/transfer/data /home/transfer/data/readonly
chmod 600 /run/authorized.keys
chmod 700 /home/transfer /home/transfer/data
chmod 500 /home/transfer/data/readonly
ln -s /etc /home/transfer/data/link
cat > /run/sshd_config <<'CONFIG'
Port 2222
ListenAddress 0.0.0.0
HostKey /fixture/host
PidFile /run/sshd.pid
AuthorizedKeysFile /run/authorized.keys
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PermitRootLogin no
UsePAM no
StrictModes yes
AllowUsers transfer
DisableForwarding yes
PermitTTY no
X11Forwarding no
MaxSessions 4
LoginGraceTime 10
LogLevel ERROR
Subsystem sftp internal-sftp
CONFIG
exec /usr/sbin/sshd -D -e -f /run/sshd_config
