import hashlib
import os
import platform
import re
from os.path import isfile
from pathlib import Path
from enum import Enum
from functools import cmp_to_key

import pkg_resources


DEBIAN_KERNEL_PKG_NAME_RE = re.compile(r'(linux-image-\d+\.\d+\.\d+-)(\d+)([.-].+)')


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


class CloudProvider(Enum):
    NONE = 0
    AMAZON = 1
    GOOGLE = 2
    MICROSOFT = 3


def detect_confinement():
    if os.getenv('SNAP'):
        return Confinement.SNAP
    is_docker = isfile('/proc/1/cgroup') and 'docker' in open('/proc/1/cgroup', 'rt').read()
    if is_docker:
        if os.getenv('BALENA') or os.getenv('RESIN'):
            return Confinement.BALENA
        else:
            return Confinement.DOCKER

    return Confinement.NONE


def is_debian():
    os_release = get_os_release()
    return os_release.get('distro_root', os_release['distro']) == 'debian'


def is_amazon_linux2():
    """
    Check if the node is running Amazon Linux 2.
    """
    os_release = get_os_release()
    return os_release.get('codename') == 'amzn2'


def detect_installation():
    if is_debian():  # For apt-based distros.
        import apt
        cache = apt.Cache()
        if 'wott-agent' in cache and __file__ in cache['wott-agent'].installed_files:
            return Installation.DEB
    elif is_amazon_linux2():  # For Amazon Linux 2.
        import rpm
        ts = rpm.ts()
        package_iterator = ts.dbMatch('name', 'python3-wott-agent')
        if package_iterator.count() > 0:
            package_header = next(package_iterator)
            if __file__.encode() in package_header[rpm.RPMTAG_FILENAMES]:
                return Installation.RPM
    # Other.
    from agent import __version__
    if isinstance(__version__, pkg_resources.Distribution):
        return Installation.PYTHON_PACKAGE
    return Installation.NONE


def detect_cloud():
    bios_version = Path('/sys/devices/virtual/dmi/id/bios_version')
    if bios_version.is_file():
        bios_version = bios_version.read_text().strip()
        if bios_version == 'Google':
            return CloudProvider.GOOGLE
        elif bios_version.endswith('.amazon'):
            return CloudProvider.AMAZON
        else:
            chassis = Path('/sys/devices/virtual/dmi/id/chassis_asset_tag')
            if chassis.is_file() and chassis.read_text().strip() == '7783-7084-3265-9085-8269-3286-77':
                return CloudProvider.MICROSOFT
    return CloudProvider.NONE


def get_packages():
    if is_debian():  # For apt-based distros.
        import apt
        cache = apt.Cache()
        packages = [deb for deb in cache if deb.is_installed]
        # Calculate packages hash.
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
    elif is_amazon_linux2():  # For Amazon Linux 2.
        import rpm
        ts = rpm.ts()
        package_iterator = ts.dbMatch()
        # All packages except for kernel.
        packages = [package_header for package_header in package_iterator if
                    package_header[rpm.RPMTAG_NAME].decode() != 'kernel']
        # Find the newest kernel package.
        package_iterator = ts.dbMatch('name', 'kernel')
        kernel_package = sorted([package_header for package_header in package_iterator],
                                key=cmp_to_key(rpm.versionCompare), reverse=True)[0]
        packages.append(kernel_package)
        # Calculate packages hash.
        packages_str = str(
            sorted((package_header[rpm.RPMTAG_NAME].decode(), package_header[rpm.RPMTAG_EVR].decode())
                   for package_header in packages))
        packages_hash = hashlib.md5(packages_str.encode()).hexdigest()
        return {
            'hash': packages_hash,
            'packages': [{
                'name': package_header[rpm.RPMTAG_NAME].decode(),
                'version': package_header[rpm.RPMTAG_EVR].decode(),
                'arch': package_header[rpm.RPMTAG_ARCH].decode() if package_header[rpm.RPMTAG_ARCH] else 'noarch',
                # Looks like there's no source name/version in the rpm package info.
                # TEMP: pass package name and version.
                'source_name': package_header[rpm.RPMTAG_NAME].decode(),
                'source_version': package_header[rpm.RPMTAG_EVR].decode()
            } for package_header in packages]
        }
    return None


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
    if is_debian():  # For apt-based distros.
        import apt_pkg
        apt_pkg.init_config()
        config = apt_pkg.config
        if 'Unattended-Upgrade' in config and 'APT::Periodic' in config:
            apt_periodic = config.subtree('APT::Periodic')
            unattended_upgrade = apt_periodic.get('Unattended-Upgrade')
            update_package_lists = apt_periodic.get('Update-Package-Lists')
            allowed_origins = config.subtree('Unattended-Upgrade').value_list('Allowed-Origins')

            # The following construction is impossible to get right with flake8. Its either E502, or W504, or E127.
            return unattended_upgrade == '1' and \
                update_package_lists == '1' and \
                '${distro_id}:${distro_codename}' in allowed_origins and \
                '${distro_id}:${distro_codename}-security' in allowed_origins
        return False
    elif is_amazon_linux2():  # For Amazon Linux 2.
        # 1. check if yum-cron installed
        # 2. check if it's running
        # 3. check if it has proper values in its config file
        import rpm
        try:
            from sh import systemctl
        except ImportError:
            # No systemd - probably yum-cron is not running
            # TODO: use "service" executable which also works without systemd and on older systems
            return False
        ts = rpm.ts()
        package_iterator = ts.dbMatch('name', 'yum-cron')
        if package_iterator.count() > 0:  # Package is installed.
            result = systemctl(['is-active', 'yum-cron'], _ok_code=[0, 3]).stdout.decode().strip()
            if result == 'active':
                config = open('/etc/yum/yum-cron.conf').read()
                if '\ndownload_updates = yes' in config and '\napply_updates = yes' in config:
                    return True
        return False
    return None


def kernel_cmdline():
    """
    Parses kernel parameters (aka cmdline).
    :return: A dict where 'name' is kernel parameter name and 'value' is its value or empty string if no value provided.
    """
    cmdline_path = Path('/proc/cmdline')
    cmdline_matches = re.compile(r"([\w\-\.]+)(\=(\"[\w\W]+\"|[\w\S]+)?)?").findall(cmdline_path.read_text())
    return {name: value.strip('"') for name, _, value in cmdline_matches}


def get_kernel_deb_package(boot_image_path):
    """
    Return a deb package instance for the currently running kernel.
    """
    import apt

    class FileFilter(apt.cache.Filter):
        def apply(self, pkg):
            return pkg.is_installed and boot_image_path in pkg.installed_files

    cache = apt.cache.FilteredCache(apt.Cache())
    cache.set_filter(FileFilter())
    kernel_debs = list(cache)
    if kernel_debs:
        return kernel_debs[0]


def get_kernel_rpm_package(boot_image_path):
    """
    Return an rpm package instance for the currently running kernel.
    """
    import rpm
    ts = rpm.ts()
    package_iterator = ts.dbMatch()
    boot_image_path_bytes = boot_image_path.encode()
    packages = [package_header for package_header in package_iterator if boot_image_path_bytes in
                package_header[rpm.RPMTAG_FILENAMES]]
    if packages:
        return packages[0]
    return None


def kernel_package_info():
    """
    Finds which currently installed deb package contains the currently running kernel.
    :return:
        If the currently running kernel was installed by deb package:
            a dict where 'source_name' and 'source_version' are the same as returned by get_packages().
        Otherwise: None
    """
    boot_image_path = kernel_cmdline().get('BOOT_IMAGE')
    if boot_image_path is None:
        return
    if is_debian():  # For apt-based distros.
        kernel_pkg = get_kernel_deb_package(boot_image_path)
        if kernel_pkg is not None:
            return {
                'name': kernel_pkg.name,
                'version': kernel_pkg.installed.version,
                'source_name': kernel_pkg.installed.source_name,
                'source_version': kernel_pkg.installed.source_version,
                'arch': kernel_pkg.installed.architecture
            }
    else:  # For Amazon Linux 2.
        import rpm
        kernel_pkg = get_kernel_rpm_package(boot_image_path)
        if kernel_pkg is not None:
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
    return None


def get_latest_same_kernel_deb(name_part0, name_part2):
    """
    Return the latest version of a deb package for given name parts.
    """
    import apt
    search_pattern = re.compile(name_part0 + r'(\d+)' + name_part2)

    class KernelFilter(apt.cache.Filter):
        """Filter class for checking for matching with a RE search pattern."""
        def apply(self, pkg):
            return pkg.is_installed and search_pattern.match(pkg.name)

    cache = apt.cache.FilteredCache(apt.Cache())
    cache.set_filter(KernelFilter())
    return sorted([(int(search_pattern.match(deb.name).group(1)), deb) for deb in cache],
                  reverse=True)[0][1]


def reboot_required():
    """
    Check if reboot required by comparing running kernel package's version
     with the newest installed kernel package's one.
    """
    boot_image_path = kernel_cmdline().get('BOOT_IMAGE')
    if boot_image_path is None:
        return None
    if is_debian():  # For apt-based distros.
        import apt_pkg
        apt_pkg.init()
        kernel_pkg = get_kernel_deb_package(boot_image_path)
        if kernel_pkg is not None:
            match = DEBIAN_KERNEL_PKG_NAME_RE.match(kernel_pkg.name)
            if match:
                name_parts = match.groups()  # E.g. ('linux-image-4.4.0-', '174', '-generic')
                latest_kernel_pkg = get_latest_same_kernel_deb(name_parts[0], name_parts[2])
                return apt_pkg.version_compare(latest_kernel_pkg.installed.version, kernel_pkg.installed.version) > 0
    else:  # For Amazon Linux 2.
        import rpm
        kernel_pkg = get_kernel_rpm_package(boot_image_path)
        if kernel_pkg is not None:
            ts = rpm.ts()
            # Find the newest kernel package.
            package_iterator = ts.dbMatch('name', 'kernel')
            latest_kernel_pkg = sorted([package_header for package_header in package_iterator],
                                       key=cmp_to_key(rpm.versionCompare), reverse=True)[0]
            return rpm.versionCompare(latest_kernel_pkg, kernel_pkg) > 0
    return None
