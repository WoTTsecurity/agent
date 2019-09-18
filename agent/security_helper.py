import crypt
from hashlib import sha256
import socket
import os
from pathlib import Path
from socket import SocketKind

import psutil
import spwd


def check_for_default_passwords(config_path):
    """
    Check if the 'pi' user current password hash is in our list of default password hashes.
    """
    base_dir = Path(config_path)
    pass_hashes_file_path = base_dir.joinpath('pass_hashes.txt')  # For deb installation.
    if not pass_hashes_file_path.is_file():
        base_dir = Path(__file__).resolve().parent.parent
        pass_hashes_file_path = base_dir.joinpath('misc/pass_hashes.txt')
    with pass_hashes_file_path.open() as f:
        read_data = f.read()

    known_passwords = {}
    for username_password in read_data.splitlines():
        username, password = username_password.split(':', maxsplit=1)
        pw = known_passwords.get(username, [])
        pw.append(password)
        known_passwords[username] = pw

    def hash_matches(pwdp, plaintext_password):
        i = pwdp.rfind('$')
        salt = pwdp[:i]
        crypted = crypt.crypt(plaintext_password, salt)
        return crypted == pwdp

    for shadow in spwd.getspall():
        encrypted_password = shadow.sp_pwdp

        for password in known_passwords.get(shadow.sp_namp, []):
            if hash_matches(encrypted_password, password):
                return True

    return False


def netstat_scan():
    """
    Returns all open inet connections with their addresses and PIDs.
    """
    connections = psutil.net_connections(kind='inet')
    return (
        [{
            'ip_version': 4 if c.family == socket.AF_INET else 6,
            'type': 'udp' if c.type == socket.SOCK_DGRAM else 'tcp',
            'local_address': c.laddr,
            'remote_address': c.raddr,
            'status': c.status if c.type == socket.SOCK_STREAM else None,
            'pid': c.pid
        } for c in connections if c.raddr],
        [{
            'ip_version': 4 if c.family == socket.AF_INET else 6,
            'host': c.laddr[0],
            'port': c.laddr[1],
            'proto': {SocketKind.SOCK_STREAM: 'tcp', SocketKind.SOCK_DGRAM: 'udp'}.get(c.type),
            'state': c.status if c.type == socket.SOCK_STREAM else None,
            'pid': c.pid
        } for c in connections if not c.raddr and c.laddr]
    )


def process_scan():
    processes = []
    for proc in psutil.process_iter():
        try:
            processes.append(proc.as_dict(attrs=[
                'pid', 'name', 'cmdline', 'username'
            ]))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes


def is_app_armor_enabled():
    """
    Returns a True/False if AppArmor is enabled.
    """
    try:
        import LibAppArmor
    except ImportError:
        # If Python bindings for AppArmor are not installed (if we're
        # running on Jessie where we can't build python3-apparmor package)
        # we resort to calling aa-status executable.
        try:
            from sh import aa_status
        except ImportError:
            return False

        # Return codes (as per aa-status(8)):
        # 0   if apparmor is enabled and policy is loaded.
        # 1   if apparmor is not enabled/loaded.
        # 2   if apparmor is enabled but no policy is loaded.
        # 3   if the apparmor control files aren't available under /sys/kernel/security/.
        # 4   if the user running the script doesn't have enough privileges to read the apparmor
        #    control files.
        return aa_status(['--enabled'], _ok_code=[0, 1, 2, 3, 4]).exit_code in [0, 2]
    else:
        return LibAppArmor.aa_is_enabled() == 1


def selinux_status():
    """
    Returns a dict as similar to:
        {'enabled': False, 'mode': 'enforcing'}
    """
    selinux_enabled = False
    selinux_mode = None

    try:
        import selinux
    except ImportError:
        # If Python bindings for SELinux are not installed (if we're
        # running on Jessie where we can't build python3-selinux package)
        # we resort to calling sestatus executable.
        try:
            from sh import sestatus
        except ImportError:
            return {'enabled': False}

        # Manually parse out the output for SELinux status
        for line in sestatus().stdout.split(b'\n'):
            row = line.split(b':')

            if row[0].startswith(b'SELinux status'):
                selinux_enabled = row[1].strip() == b'enabled'

            if row[0].startswith(b'Current mode'):
                selinux_mode = row[1].strip()
    else:
        if selinux.is_selinux_enabled() == 1:
            selinux_enabled = True
            selinux_mode = {-1: None, 0: 'permissive', 1: 'enforcing'}[selinux.security_getenforce()]
    return {'enabled': selinux_enabled, 'mode': selinux_mode}


AUDITED_CONFIG_FILES = [
    '/etc/passwd',
    '/etc/shadow',
    '/etc/group'
]
SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'
SSHD_CONFIG_DEFAULTS = {
    'PermitEmptyPasswords': 'no',
    'PermitRootLogin': 'yes',
    'PasswordAuthentication': 'yes',
    'AllowAgentForwarding': 'yes',
    'Protocol': '2,1'
}
BLOCK_SIZE = 64 * 1024


def audit_config_files():
    """
    For a predefined list of system config files (see AUDITED_CONFIG_FILES)
    get their last modified time and SHA256 hash.
    The same info regarding SSHD_CONFIG_PATH is appended (see audit_sshd below),
    :return: [{'name': ..., 'sha256': ..., 'last_modified': ...}]
    """

    def digest_sha256(file_path):
        h = sha256()

        with open(file_path, 'rb') as file:
            while True:
                # Reading is buffered, so we can read smaller chunks.
                chunk = file.read(BLOCK_SIZE)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest()

    def audit_common(file_path):
        return {
            'name': file_path,
            'sha256': digest_sha256(file_path),
            'last_modified': os.path.getmtime(file_path)
        }

    audited_files = [audit_common(file_path) for file_path in AUDITED_CONFIG_FILES if os.path.isfile(file_path)]
    if os.path.isfile(SSHD_CONFIG_PATH):
        audited_sshd = audit_common(SSHD_CONFIG_PATH)
        audited_sshd['issues'] = audit_sshd()
        audited_files.append(audited_sshd)
    return audited_files


def audit_sshd():
    """
    Read and parse SSHD_CONFIG_PATH, detect all unsafe parameters.
    :return: a dict where key is an unsafe parameter and value is its (unsafe) value.
    """
    issues = {}
    config = SSHD_CONFIG_DEFAULTS.copy()

    with open(SSHD_CONFIG_PATH) as sshd_config:
        for line in sshd_config:
            line = line.strip()
            if not line or line[0] == '#':
                # skip empty lines and comments
                continue

            line_split = line.split(maxsplit=1)
            if len(line_split) != 2:
                # skip invalid lines
                continue

            parameter, value = line_split
            value = value.strip('"')
            if parameter in SSHD_CONFIG_DEFAULTS:
                config[parameter] = value

    unsafe_yes = ['PermitEmptyPasswords', 'PermitRootLogin', 'PasswordAuthentication', 'AllowAgentForwarding']
    issues = {parameter: config[parameter] for parameter in unsafe_yes if config[parameter] == 'yes'}
    if config['Protocol'] != '2':
        issues['Protocol'] = config['Protocol']
    return issues
