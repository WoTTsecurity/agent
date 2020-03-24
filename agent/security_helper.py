import copy
import crypt
import logging
import os
import shutil
import socket
import subprocess
import time
from enum import IntEnum
from hashlib import sha256
from pathlib import Path
from socket import SocketKind

import psutil
import spwd
from sh import ErrorReturnCode_1, ErrorReturnCode_255

from .os_helper import CloudProvider, detect_cloud, is_debian, kernel_cmdline, confirmation

logger = logging.getLogger('agent')


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

    usernames = set()
    for shadow in spwd.getspall():
        encrypted_password = shadow.sp_pwdp

        for password in known_passwords.get(shadow.sp_namp, []):
            if hash_matches(encrypted_password, password):
                usernames.add(shadow.sp_namp)

    return list(usernames)


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
            proc_info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'username'])
            cpuset = Path('/proc/{}/cpuset'.format(proc_info['pid']))
            if cpuset.exists():
                with cpuset.open() as cpuset_file:
                    if cpuset_file.read().startswith('/docker/'):
                        proc_info['container'] = 'docker'
            processes.append(proc_info)
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
BLOCK_SIZE = 64 * 1024
SSHD_CONFIG_PATH = '/etc/ssh/sshd_config'


class SshdConfigParam:
    class COMPARE(IntEnum):
        MATCH = 1
        RANGE = 2

    def match(self, val: str) -> bool:
        return self._safe == val

    def range(self, val: str) -> bool:
        vmin, vmax = self._safe
        return vmin <= int(val) <= vmax

    @property
    def safe_value(self) -> str:
        return self._safe_value

    def __init__(self, default, safe, compare=COMPARE.MATCH):
        self.default = default
        self._safe = safe
        self.is_safe = {self.COMPARE.MATCH: self.match,
                        self.COMPARE.RANGE: self.range}[compare]
        self._safe_value = (safe if compare == self.COMPARE.MATCH else str(self._safe[1]))


SSHD_CONFIG_PARAMS_INFO = {
    'PermitEmptyPasswords': SshdConfigParam('no', 'no'),
    'PermitRootLogin': SshdConfigParam('yes', 'no'),
    'PasswordAuthentication': SshdConfigParam('yes', 'no'),
    'AllowAgentForwarding': SshdConfigParam('yes', 'no'),
    'Protocol': SshdConfigParam('2', '2'),
    'ClientAliveInterval': SshdConfigParam('0', (1, 300), SshdConfigParam.COMPARE.RANGE),
    'ClientAliveCountMax': SshdConfigParam('3', (0, 3), SshdConfigParam.COMPARE.RANGE),
    'HostbasedAuthentication': SshdConfigParam('no', 'no'),
    'IgnoreRhosts': SshdConfigParam('yes', 'yes'),
    'LogLevel': SshdConfigParam('INFO', 'INFO'),
    'LoginGraceTime': SshdConfigParam('120', (1, 60), SshdConfigParam.COMPARE.RANGE),
    'MaxAuthTries': SshdConfigParam('6', (0, 4), SshdConfigParam.COMPARE.RANGE),
    'PermitUserEnvironment': SshdConfigParam('no', 'no'),
    'X11Forwarding': SshdConfigParam('no', 'no')
}


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
    sshd_version = None
    try:
        from sh import sshd
    except ImportError:
        pass
    else:
        sshd_help = sshd(['--help'], _ok_code=[1]).stderr
        sshd_help_lines = sshd_help.splitlines()
        for l in sshd_help_lines:
            if l.startswith(b'OpenSSH_'):
                sshd_version = float(l.lstrip(b'OpenSSH_')[:3])
                break
    config = copy.deepcopy(SSHD_CONFIG_PARAMS_INFO)
    if sshd_version is not None and sshd_version >= 7.0:
        # According to https://www.openssh.com/releasenotes.html those things were changed in 7.0.
        del (config['Protocol'])
        config['PermitRootLogin'].default = 'prohibit-password'

    # Fill the dict with default values which will be updated with found config parameters' values.
    insecure_params = {k: config[k].default for k in config}
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
            if parameter in insecure_params:
                insecure_params[parameter] = value
    issues = {}
    for param in insecure_params:
        if not config[param].is_safe(insecure_params[param]):
            issues[param] = insecure_params[param]
    return issues


def mysql_root_access():
    try:
        subprocess.check_call(["mysql", "-uroot", "-eSHOW DATABASES;"], timeout=5,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        # Non-zero exit code: can't connect to server, root password is set (code 1 in both cases), or SIGSEGV.
        if e.returncode == 1:
            return False
    except (FileNotFoundError, PermissionError):
        # Can't execute mysql client.
        pass


def cpu_vulnerabilities():
    """
    Query sysfs for CPU vulnerabilities mitigation.
    :return: A dict where
        'vendor': "Vendor ID" field returned by lscpu. Possible values: GenuineIntel, AuthenticAMD, ARM.
        'vulnerable': False if not vulnerable, True if vulnerable, None if in doubt. Present if vendor is GenuineIntel.
        'mitigations_disabled': whether any mitigation was disabled in kernel cmdline. Present if vulnerable is None.
    """
    from sh import lscpu
    os.environ['LC_ALL'] = 'en_US'  # switch language to English to be able to parse lscpu output.
    vendor_id = None
    for line in lscpu().stdout.decode().split('\n'):
        param = line.split(':', 1)
        if param and param[0] == 'Vendor ID':
            vendor_id = param[1].strip()
            break
    # TODO: switch LC_ALL back?

    res = {'vendor': vendor_id}
    if vendor_id != "GenuineIntel":
        # Not an Intel CPU, most probably not vulnerable
        return res

    sys_vulnerabilities = Path('/sys/devices/system/cpu/vulnerabilities')
    if not sys_vulnerabilities.is_dir():
        # Directory does not exist: either smth is bind-mounted over it or the kernel is too old.
        vulnerable = None
    else:
        vulnerable = False
        vulns = ['l1tf', 'meltdown', 'spectre_v1', 'spectre_v2']
        if detect_cloud() != CloudProvider.AMAZON:
            # AWS reports no mitigation for those vulnerabilities, as if they are not mitigated at all.
            # But we decided to trust AWS and assume it's not vulnerable.
            vulns += ['spec_store_bypass', 'mds']
        for name in vulns:
            status_file = sys_vulnerabilities / name
            if status_file.is_file():
                # If CPU is not prone to this vulnerability the status file will start with
                # 'Not affected' or 'Mitigation: ...'. Otherwise it will start with 'Vulnerable: ...'.
                if status_file.read_text().startswith('Vulnerable'):
                    vulnerable = True
                    break
            else:
                # Status file does not exist: smth is bind-mounted over it or the kernel is not completely patched.
                vulnerable = None
                break

    res['vulnerable'] = vulnerable

    # If we can't confidently tell if CPU is vulnerable we search cmdline for mitigation disablement params and let
    # the server do the rest.
    if vulnerable is None:
        mitigations_disabled = False
        mitigation_cmdline_params = {
            'nopti': '',
            'nospectre_v1': '',
            'nospectre_v2': '',
            'mds': 'off',
            'pti': 'off',
            'mitigations': 'off',
            'spectre_v2': 'off',
            'spectre_v2_user': 'off',
            'spec_store_bypass_disable': 'off'
        }
        cmdline = kernel_cmdline()
        for pname, pvalue in mitigation_cmdline_params.items():
            if cmdline.get(pname) == pvalue:
                mitigations_disabled = True
                break
        res['mitigations_disabled'] = mitigations_disabled

    return res


def patch_sshd_config(patch_param):
    from . import BACKUPS_PATH

    param_info = SSHD_CONFIG_PARAMS_INFO[patch_param]
    if not os.path.isfile(SSHD_CONFIG_PATH):
        logger.error('{} not found'.format(SSHD_CONFIG_PATH))
        return
    try:
        from sh import sshd, service
    except ImportError:
        logger.exception('sshd or service executable not found')
        return

    safe_value_string = '\n# Added by wott-agent on {}\n{} {}\n'.format(time.ctime(), patch_param, param_info.safe_value)
    backup_filename = os.path.join(BACKUPS_PATH, 'sshd_config.' + str(int(time.time())))
    replaced = False

    with open(SSHD_CONFIG_PATH, 'r+') as sshd_config:
        safe = False
        lines = sshd_config.readlines()
        patched_lines = []
        for line in lines:
            patched_lines.append(line)
            line = line.strip()
            if not line or line[0] == '#':
                # skip empty lines and comments
                continue
            line_split = line.split(maxsplit=1)
            if len(line_split) != 2:
                continue
            param, value = line_split
            value = value.strip('"')
            if param == patch_param:
                if not param_info.is_safe(value):
                    logger.info('{}: replacing "{}" with "{}"'.format(param, value, param_info.safe_value))
                    patched_lines[-1] = safe_value_string
                    replaced = True
                    safe = False
                else:
                    safe = True
        if not replaced and not safe and not param_info.is_safe(param_info.default):
            logger.info('{}: replacing default "{}" with "{}"'.format(patch_param, param_info.default, param_info.safe_value))
            patched_lines.append(safe_value_string)
            replaced = True
        if replaced:
            if patch_param == 'PasswordAuthentication':
                if not confirmation(
                        "Warning: Before you disable password authentication, make sure that you have generated "
                        "and installed your SSH keys on this server. Failure to do so will result in that you "
                        "will be locked out. I have have my SSH key(s) installed:"):
                    return
            logger.info('Backing up {} as {}'.format(SSHD_CONFIG_PATH, backup_filename))
            shutil.copy(SSHD_CONFIG_PATH, backup_filename)
            logger.info('Writing {}'.format(SSHD_CONFIG_PATH))
            sshd_config.seek(0, 0)
            sshd_config.truncate()
            sshd_config.writelines(patched_lines)
        else:
            logger.info('Nothing to patch.')
            return

    try:
        sshd('-t')
    except ErrorReturnCode_255 as e:
        if e.stderr.startswith(SSHD_CONFIG_PATH.encode()):
            logger.exception('{} is invalid. Restoring from backup.'.format(SSHD_CONFIG_PATH))
            shutil.copy(backup_filename, SSHD_CONFIG_PATH)
        else:
            logger.exception('something went wrong')
        return

    try:
        service_name = 'ssh' if is_debian() else 'sshd'
        service([service_name, 'reload'])
    except ErrorReturnCode_1:
        logger.exception('failed to reload sshd.')
    else:
        logger.info('sshd reloaded.')
