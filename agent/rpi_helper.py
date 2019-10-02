import hashlib
import os
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
        import apt
        cache = apt.Cache()
        if __file__ in cache['wott-agent'].installed_files:
            return Installation.DEB
    finally:
        if isinstance(agent.__version__, pkg_resources.Distribution):
            return Installation.PYTHON_PACKAGE
        return Installation.NONE


def get_deb_packages():
    import apt
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
