import crypt
import socket
from pathlib import Path
from socket import SocketKind
import spwd

import psutil


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


def get_process_info(pid):
    """
    Collect all required info for given process id.
    """
    process = psutil.Process(pid)
    process_info = {'name': process.name(), 'user': process.username()}
    process_cmdline = list(process.cmdline())
    # 1-element command line is useless.
    process_info['cmdline'] = process_cmdline if len(process_cmdline) > 1 else []
    return process_info


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
            'process_info': get_process_info(c.pid)
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
        from sh import aa_status
    except ImportError:
        return False

    # Returns 0 if enabled and 1 if disable
    get_aa_status = aa_status(['--enabled'], _ok_code=[0, 1]).exit_code
    if get_aa_status == 1:
        return False
    return True


def selinux_status():
    """
    Returns a dict as similar to:
        {'enabled': False, 'mode': 'enforcing'}
    """
    selinux_enabled = None
    selinux_mode = None

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

    return {'enabled': selinux_enabled, 'mode': selinux_mode}
