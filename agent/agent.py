#!/usr/bin/env python3

import cfssl
import hashlib
import json
import os
import sh
import sys
import OpenSSL.crypto
from pathlib import Path
from time import sleep
from datetime import datetime, timedelta


CFSSL_SERVER = os.getenv('CFSSL_SERVER')
CFSSL_PORT = int(os.getenv('CFSSL_PORT', 8888))
CERT_PATH = os.getenv('CERT_PATH', '/opt/wott/certs')
RENEWAL_THRESHOLD = 15


def time_for_certificate_renewal():
    """ Check if it's time for certificate renewal """
    client_cert = Path(os.path.join(CERT_PATH, 'client.crt'))

    # No cert is the same essentially.
    if not client_cert.is_file():
        return True

    with open(client_cert, 'rt') as f:
        cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                f.read()
                )
        expiration_date = cert.get_notAfter()

    # Ugly workaround for date parsing
    cert_expiration_time = datetime.strptime(expiration_date[0:-2].decode(), '%Y%m%d%H%M%S')
    return datetime.utcnow() + timedelta(days=RENEWAL_THRESHOLD) > cert_expiration_time


def generate_uuid():
    """
    This function is simply a PoC and is not cryptographically sound.
    """

    serial = None
    revision = None
    hardware = None

    with open('/proc/cpuinfo', 'r') as f:

        def get_value(line, k):
            return line.split()[-1]

        for line in f.readlines():
            if 'Serial' in line:
                serial = get_value(line, 'Serial')

            if 'Revision' in line:
                revision = get_value(line, 'Revision')

            if 'Hardware' in line:
                hardware = get_value(line, 'Hardware')

    if not (serial and revision and hardware):
        print("Not a Raspberry Pi. Setting temporary placeholder.")
        hostname = 'dev-instance'
    else:
        hostname = hashlib.sha512('{}-{}-{}'.format(serial, revision, hardware).encode('utf-8')).hexdigest()[0:32]

    return '{}.d.wott.io'.format(hostname)


def generate_cert(device_uuid):
    client_input = {
            "CN": "{}".format(device_uuid),
            "key": {
                "algo": "ecdsa",
                "size": 256
            },
            "names": [
                {
                    "C": "US",
                    "ST": "CA",
                    "L": "San Francisco"
                }
            ]
    }

    cert = sh.cfssl.genkey('-', _in=json.dumps(client_input, indent=4))
    if cert.exit_code != 0:
        print("Certificate generation failed.")
        sys.exit(1)
    return json.loads(str(cert))


def sign_cert(csr, device_uuid):
    cf = cfssl.cfssl.CFSSL(
            host=CFSSL_SERVER,
            port=CFSSL_PORT,
            ssl=False
    )

    ca = cf.info(label='primary')

    crt_req = cf.sign(
        certificate_request=csr,
        hosts=['{}'.format(device_uuid)]
    )

    return {'crt': crt_req, 'ca': ca['certificate']}


def main():
    while True:
        if not time_for_certificate_renewal():
            print("Certificate is valid. No need for renewal.")
        else:
            device_uuid = generate_uuid()
            print('Got hostname: {}'.format(device_uuid))

            print('Generating certificate...')
            gen_key = generate_cert(device_uuid)

            print('Submitting CSR...')
            crt = sign_cert(gen_key['csr'], device_uuid)

            print('Writing certificate and key to disk...')
            client_cert = Path(os.path.join(CERT_PATH, 'client.crt'))
            client_key = Path(os.path.join(CERT_PATH, 'client.key'))
            ca_cert = Path(os.path.join(CERT_PATH, 'ca.crt'))

            with open(client_cert, 'w') as f:
                f.write(crt['crt'])

            with open(ca_cert, 'w') as f:
                f.write(crt['ca'])

            with open(client_key, 'w') as f:
                f.write(gen_key['key'])

        sleep(3600)


if __name__ == "__main__":
    main()
