import os


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


def detect_confinement():
    """
    Returns the confinement environment.
    This function is used to control features.
    """

    metadata = {
        'docker': None,
        'balena': None,
        'snap': None,
    }

    # Detect if running inside Docker
    # Credits: https://stackoverflow.com/a/42674935/346054
    with open('/proc/1/cgroup', 'rt') as ifh:
        metadata['docker'] = 'docker' in ifh.read()

    # Detect if running inside Balena
    if os.getenv('BALENA', False) or os.getenv('RESIN', False):
        metadata['balena'] = True

    # Detect if running inside an Ubuntu Snap
    if os.getenv('SNAP', False):
        metadata['snap'] = True

    return metadata
