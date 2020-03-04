import hashlib
import os
import platform
import re
from pathlib import Path
from enum import Enum
import pkg_resources

import agent


def detect_raspberry_pi():
    metadata = {
        'is_raspberry_pi': None,
        'hardware_model': None,
        'serial_number': None
    }

    proc_model = Path('/proc/device-tree/model')
    proc_serial = Path('/proc/device-tree/serial-number')

    if proc_model.is_file():
        model = proc_model.open().read().strip('\0')
        metadata['hardware_model'] = model
        metadata['is_raspberry_pi'] = model.startswith('Raspberry Pi')

    if proc_serial.is_file():
        metadata['serial_number'] = proc_serial.open().read().strip('\0')

    return metadata


class Confinement(Enum):
    NONE = 0
    DOCKER = 1
    BALENA = 2
    SNAP = 3


class Installation(Enum):
    NONE = 0
    DEB = 1
    PYTHON_PACKAGE = 2
    RPM = 3


def detect_confinement():
    if os.getenv('SNAP'):
        return Confinement.SNAP
    is_docker = 'docker' in open('/proc/1/cgroup', 'rt').read()
    if is_docker:
        if os.getenv('BALENA') or os.getenv('RESIN'):
            return Confinement.BALENA
        else:
            return Confinement.DOCKER

    return Confinement.NONE


def detect_installation():
    # For apt-based distros.
    try:
        import apt
    except ModuleNotFoundError:
        # For rpm-based distros.
        try:
            import rpm
        except ModuleNotFoundError:
            pass
        else:
            ts = rpm.ts()
            mi = ts.dbMatch('name', 'wott-agent')
            if mi.count() > 0:
                package_header = mi.__next__()
                if __file__.encode() in package_header[rpm.RPMTAG_FILENAMES]:
                    return Installation.RPM
    else:
        cache = apt.Cache()
        if __file__ in cache['wott-agent'].installed_files:
            return Installation.DEB
    # Other.
    if isinstance(agent.__version__, pkg_resources.Distribution):
        return Installation.PYTHON_PACKAGE
    return Installation.NONE


def get_packages():
    # For apt-based distros.
    try:
        import apt
    except ModuleNotFoundError:
        # For rpm-based distros.
        import rpm
        ts = rpm.ts()
        mi = ts.dbMatch()
        packages = [package_header for package_header in mi]
        packages_str = str(
            sorted((package_header[rpm.RPMTAG_NAME].decode(), package_header[rpm.RPMTAG_EVR].decode())
                   for package_header in packages))
        packages_hash = hashlib.md5(packages_str.encode()).hexdigest()
        return {
            'hash': packages_hash,
            'packages': [{
                'name': package_header[rpm.RPMTAG_NAME].decode(),
                'version': package_header[rpm.RPMTAG_EVR].decode(),
                'arch': package_header[rpm.RPMTAG_ARCH].decode() if package_header[rpm.RPMTAG_ARCH] is not None
                else 'noarch',
                # Looks like there's no source name/version in the rpm package info.
                # TEMP: pass package name and version.
                'source_name': package_header[rpm.RPMTAG_NAME].decode(),
                'source_version': package_header[rpm.RPMTAG_EVR].decode()
            } for package_header in packages]
        }
    else:
        cache = apt.Cache()
        packages = [deb for deb in cache if deb.is_installed]
        packages_str = str(sorted((deb.installed.package.name, deb.installed.version) for deb in packages))
        packages_hash = hashlib.md5(packages_str.encode()).hexdigest()
        return {
            'hash': packages_hash,
            'packages': [{
                'name': deb.installed.package.name,
                'version': deb.installed.version,
                'arch': deb.installed.architecture,
                'source_name': deb.installed.source_name,
                'source_version': deb.installed.source_version
            } for deb in packages]
        }


def get_os_release():
    """
    Returns a dict with the following items:
    distro: Concrete distro name. Examples: raspbian, ubuntu, debian, ubuntu-core.
    version: Short, numerical version. Examples: 9, 18.04, 18.
    distro_root: The root distro (from which the distro was branched). Optional. Examples: debian.
    full_version: Longer, human-readable version. Optional. Examples (last one is from ubuntu-core):
        "9 (stretch)", "18.04.3 LTS (Bionic Beaver)", 18
    codename: Distro version codename. Optional. Examples: stretch, bionic.
    """

    os_release = Path('/etc/os-release')
    # Normally this file should be present on any Linux system starting with Jessie (and not only Debian).

    # But we may be running in some pre-2012 system...
    if not os_release.is_file():
        # hopefully Python can give us at least some info
        # FIXME: linux_distribution is removed since Python 3.7
        name, version, codename = platform.linux_distribution()
        return {'distro': name, 'version': version, 'codename': codename}

    PARAM_NAMES = {
        'ID': 'distro',
        'ID_LIKE': 'distro_root',
        'VERSION_ID': 'version',
        'VERSION': 'full_version',
        'VERSION_CODENAME': 'codename'
    }
    with os_release.open() as os_release_file:
        lines = os_release_file.read().splitlines()
        os_info = {PARAM_NAMES[param]: value.strip('"') for param, value in map(
            lambda line: line.split('=', 1), lines) if param in PARAM_NAMES}
        # Set proper codename for Debian/Raspbian Jessie.
        if 'codename' not in os_info and os_info.get('distro', '') in ('debian', 'raspbian') and \
                os_info.get('version', '') == '8':
            os_info['codename'] = 'jessie'
        # Set proper codename for Amazon Linux 2.
        if 'codename' not in os_info and os_info.get('distro', '') == 'amzn' and os_info.get('version', '') == '2':
            os_info['codename'] = 'amzn2'
        return os_info


def auto_upgrades_enabled():
    """
    Checks if auto-updates are enabled on a system.
    :return: boolean
    """
    # For apt-based distros.
    try:
        import apt_pkg
    except ModuleNotFoundError:
        # For rpm-based distros.
        # 1. check if yum-cron installed
        # 2. check if it's running
        # 3. check if it has proper values in its config file
        import rpm
        from sh import systemctl
        ts = rpm.ts()
        mi = ts.dbMatch('name', 'yum-cron')
        if mi.count() > 0:  # Package is installed.
            result = systemctl(['is-active', 'yum-cron'], _ok_code=[0, 3]).stdout.decode().strip()
            if result == 'active':
                config = open('/etc/yum/yum-cron.conf').read()
                if '\ndownload_updates = yes' in config and '\napply_updates = yes' in config:
                    return True
    else:
        apt_pkg.init_config()
        config = apt_pkg.config
        if 'Unattended-Upgrade' in config and 'APT::Periodic' in config:
            apt_periodic = config.subtree('APT::Periodic')
            unattended_upgrade = apt_periodic.get('Unattended-Upgrade')
            update_package_lists = apt_periodic.get('Update-Package-Lists')
            allowed_origins = config.subtree('Unattended-Upgrade').value_list('Allowed-Origins')
            return unattended_upgrade == '1' and \
                update_package_lists == '1' and \
                '${distro_id}:${distro_codename}' in allowed_origins and \
                '${distro_id}:${distro_codename}-security' in allowed_origins
    return False


def kernel_cmdline():
    """
    Parses kernel parameters (aka cmdline).
    :return: A dict where 'name' is kernel parameter name and 'value' is its value or empty string if no value provided.
    """
    cmdline_path = Path('/proc/cmdline')
    cmdline_matches = re.compile(r"([\w\-\.]+)(\=(\"[\w\W]+\"|[\w\S]+)?)?").findall(cmdline_path.read_text())
    return {name: value.strip('"') for name, _, value in cmdline_matches}


def kernel_package():
    """
    Finds which currently installed deb package contains the currently running kernel.
    :return:
        If the currently running kernel was installed by deb package:
            a dict where 'source_name' and 'source_version' are the same as returned by get_packages().
        Otherwise: None
    """
    boot_image = kernel_cmdline().get('BOOT_IMAGE')
    if not boot_image:
        return
    # For apt-based distros.
    try:
        import apt
    except ModuleNotFoundError:
        # For rpm-based distros.
        import rpm
        ts = rpm.ts()
        mi = ts.dbMatch()
        packages = [package_header for package_header in mi if boot_image.encode() in
                    package_header[rpm.RPMTAG_FILENAMES]]
        if packages:
            kernel_pkg = packages[0]
            return {
                'name': kernel_pkg[rpm.RPMTAG_NAME].decode(),
                'version': kernel_pkg[rpm.RPMTAG_EVR].decode(),
                'arch': kernel_pkg[rpm.RPMTAG_ARCH].decode() if kernel_pkg[rpm.RPMTAG_ARCH] is not None
                else 'noarch',
                # Looks like there's no source name/version in the rpm package info.
                # TEMP: pass package name and version.
                'source_name': kernel_pkg[rpm.RPMTAG_NAME].decode(),
                'source_version': kernel_pkg[rpm.RPMTAG_EVR].decode()
            }
    else:
        class FileFilter(apt.cache.Filter):
            def apply(self, pkg):
                return pkg.is_installed and boot_image in pkg.installed_files
        cache = apt.cache.FilteredCache(apt.Cache())
        cache.set_filter(FileFilter())
        kernel_deb = list(cache)
        if kernel_deb:
            kernel_pkg = kernel_deb[0].installed
            return {
                'name': kernel_pkg.package.name,
                'version': kernel_pkg.version,
                'source_name': kernel_pkg.source_name,
                'source_version': kernel_pkg.source_version,
                'arch': kernel_pkg.architecture,
            }
