from sh import lsb_release


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


def get_distro():
    return {
        'id': lsb_release(['-i', '-s']).split()[0],  # --id --short
        'release': lsb_release(['-r', '-s']).split()[0]
    }
