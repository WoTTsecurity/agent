#!/usr/bin/env python3

import hashlib
import json
import os
import sh
import sys
import OpenSSL.crypto
import requests
from pathlib import Path
from time import sleep
from datetime import datetime, timedelta


WOTT_ENDPOINT = 'https://api.wott.io'
CERT_PATH = os.getenv('CERT_PATH', '/opt/wott/certs')
RENEWAL_THRESHOLD = 15


def time_for_certificate_renewal():
    """ Check if it's time for certificate renewal """

    client_cert_path = os.path.join(CERT_PATH, 'client.crt')
    client_cert = Path(client_cert_path)

    # No cert is the same essentially.
    if not client_cert.is_file():
        return True

    # Make sure there is no empty cert on disk
    if os.path.getsize(client_cert_path) == 0:
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


def get_device_id():
    """
    Device ID is generated remotely.
    """
    device_id_request = requests.get(
            '{}/v0.1/generate-cert'.format(WOTT_ENDPOINT)
            ).json()
    return device_id_request['device_id']


def generate_cert(device_id):
    client_input = {
            "CN": "{}".format(device_id),
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


def sign_cert(csr, device_id):
    ca = requests.get('{}/v0.1/ca'.format(WOTT_ENDPOINT))

    if not ca.ok:
        print('Failed to get CA...')
        print(ca.status_code)
        print(ca.content)
        return

    payload = {
            'csr': csr,
            'device_id': device_id,
            }

    crt_req = requests.post(
            '{}/v0.1/sign'.format(WOTT_ENDPOINT),
            json=payload
            )

    if not crt_req.ok:
        print('Failed to submit CSR...')
        print(crt_req.status_code)
        print(crt_req.content)
        return

    return {'crt': crt_req.json()['crt'], 'ca': ca.json()['ca']}


def main():
    while True:
        if not time_for_certificate_renewal():
            print("Certificate is valid. No need for renewal.")
        else:
            device_id = get_device_id()
            print('Got hostname: {}'.format(device_id))

            print('Generating certificate...')
            gen_key = generate_cert(device_id)

            print('Submitting CSR...')
            crt = sign_cert(gen_key['csr'], device_id)

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

        print('Going to sleep...')
        sleep(3600)


if __name__ == "__main__":
    main()
