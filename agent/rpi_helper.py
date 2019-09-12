import hashlib
import os
from enum import Enum
import pkg_resources

import apt

import agent


def detect_raspberry_pi():
    metadata = {
        'is_raspberry_pi': None,
        'hardware_model': None,
        'serial_number': None
    }

    with open('/proc/cpuinfo') as f:
        cpuinfo = f.readlines()

    # Assume it is a Raspberry Pi if these three elements are present.
    metadata['is_raspberry_pi'] = 'Hardware' in str(cpuinfo) and 'Revision' in str(cpuinfo) and 'Serial' in str(cpuinfo)

    if metadata['is_raspberry_pi']:
        for line in cpuinfo:
            if line.startswith('Revision'):
                metadata['hardware_model'] = line.split()[-1]
            if line.startswith('Serial'):
                metadata['serial_number'] = line.split()[-1]

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
    try:
        cache = apt.Cache()
        if __file__ in cache['wott-agent'].installed_files:
            return Installation.DEB
    finally:
        if isinstance(agent.__version__, pkg_resources.Distribution):
            return Installation.PYTHON_PACKAGE
        return Installation.NONE


def get_deb_packages():
    cache = apt.Cache()
    packages = [deb for deb in cache if deb.is_installed]
    packages_str = str(sorted((deb.installed.package.name, deb.installed.version) for deb in packages))
    packages_hash = hashlib.md5(packages_str.encode()).hexdigest()
    return {
        'hash': packages_hash,
        'packages': [{
            'name': deb.installed.package.name,
            'version': deb.installed.version,
            'arch': deb.installed.architecture
        } for deb in packages]
    }
