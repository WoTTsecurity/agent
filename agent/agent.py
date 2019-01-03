#!/usr/bin/env python3

import os
import requests
import datetime

from pathlib import Path
from time import sleep
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

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

    with open(client_cert_path, 'r') as f:
        cert = x509.load_pem_x509_certificate(f.read().encode(), default_backend())

    return datetime.datetime.utcnow() + datetime.timedelta(days=RENEWAL_THRESHOLD) > cert.not_valid_after


def get_device_id():
    """
    Device ID is generated remotely.
    """
    device_id_request = requests.get(
            '{}/v0.1/generate-id'.format(WOTT_ENDPOINT)
            ).json()
    return device_id_request['device_id']


def generate_cert(device_id):
    private_key = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    builder = x509.CertificateSigningRequestBuilder()

    builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'{}'.format(device_id)),
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'UK'),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'London'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Web of Trusted Things'),
            ]))

    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    serialized_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    serialized_csr = csr.public_bytes(serialization.Encoding.PEM)

    return {
        'csr': serialized_csr.decode(),
        'key': serialized_private_key.decode()
    }


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


def renew_cert():
    pass


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
            client_combined = Path(os.path.join(CERT_PATH, 'combined.pem'))
            ca_cert = Path(os.path.join(CERT_PATH, 'ca.crt'))

            with open(client_cert, 'w') as f:
                f.write(crt['crt'])

            with open(ca_cert, 'w') as f:
                f.write(crt['ca'])

            with open(client_key, 'w') as f:
                f.write(gen_key['key'])

            with open(client_combined, 'w') as f:
                f.write(gen_key['key'])
                f.write(crt['crt'])

        print('Going to sleep...')
        sleep(3600)


if __name__ == "__main__":
    main()
