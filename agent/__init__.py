import os
import requests
import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from math import floor
from pathlib import Path
from sys import exit

WOTT_ENDPOINT = 'https://api.wott.io'

# Conditional handling for if we're running
# inside a Snap.
if os.getenv('SNAP_NAME'):
    CERT_PATH = os.getenv('SNAP_DATA')
else:
    CERT_PATH = os.getenv('CERT_PATH', '/opt/wott/certs')

# This needs to be adjusted once we have
# changed the certificate life span from 7 days.
RENEWAL_THRESHOLD = 3

CLIENT_CERT_PATH = os.path.join(CERT_PATH, 'client.crt')
CLIENT_KEY_PATH = os.path.join(CERT_PATH, 'client.key')
CA_CERT_PATH = os.path.join(CERT_PATH, 'ca.crt')
COMBINED_PEM_PATH = os.path.join(CERT_PATH, 'combined.pem')


def is_bootstrapping():
    client_cert = Path(CLIENT_CERT_PATH)

    if not client_cert.is_file():
        print('No certificate found on disk.')
        return True

    # Make sure there is no empty cert on disk
    if os.path.getsize(CLIENT_CERT_PATH) == 0:
        print('Certificate found but it is broken')
        return True

    return False


def get_certificate_expiration_date():
    """
    Returns the expiration date of the certificate.
    """

    with open(CLIENT_CERT_PATH, 'r') as f:
        cert = x509.load_pem_x509_certificate(f.read().encode(), default_backend())

    return cert.not_valid_after


def time_for_certificate_renewal():
    """ Check if it's time for certificate renewal """
    return datetime.datetime.utcnow() + datetime.timedelta(days=RENEWAL_THRESHOLD) > get_certificate_expiration_date()


def generate_device_id():
    """
    Device ID is generated remotely.
    """
    device_id_request = requests.get(
            '{}/v0.1/generate-id'.format(WOTT_ENDPOINT)
            ).json()
    return device_id_request['device_id']


def get_device_id():
    """
    Returns the WoTT Device ID (i.e. fqdn) by reading the first subject from
    the certificate on disk.
    """

    with open(CLIENT_CERT_PATH, 'r') as f:
        cert = x509.load_pem_x509_certificate(f.read().encode(), default_backend())
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


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

    builder = builder.add_extension(
        x509.SubjectAlternativeName(
            [x509.DNSName(u'{}'.format(device_id))]
        ),
        critical=False
    )

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


def get_ca_cert():
    ca = requests.get('{}/v0.1/ca'.format(WOTT_ENDPOINT))

    if not ca.ok:
        print('Failed to get CA...')
        print(ca.status_code)
        print(ca.content)
        return

    return ca.json()['ca']


def sign_cert(csr, device_id):
    """
    This is the function for the initial certificate generation.
    This is only valid for the first time. Future renewals require the
    existing certificate to renew.
    """

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

    return {'crt': crt_req.json()['crt']}


def renew_cert(csr, device_id):
    """
    This is the renewal function. We need to use the existing certificate to
    verify ourselves in order to get a renewed certificate
    """

    print('Attempting to renew certificate...')

    payload = {
            'csr': csr,
            'device_id': device_id,
            }

    crt_req = requests.post(
        'https://renewal-api.wott.io/v0.1/sign',
        verify=CA_CERT_PATH,
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
        json=payload
        )

    if not crt_req.ok:
        print('Failed to submit CSR...')
        print(crt_req.status_code)
        print(crt_req.content)
        return

    return {'crt': crt_req.json()['crt']}


def main():
    bootstrapping = is_bootstrapping()

    if bootstrapping:
        device_id = generate_device_id()
        print('Got WoTT ID: {}'.format(device_id))
    else:
        if not time_for_certificate_renewal():
            time_to_cert_expires = get_certificate_expiration_date() - datetime.datetime.now()
            print("Certificate expires in {} days and {} hours. No need for renewal. Going to sleep...".format(
                time_to_cert_expires.days,
                floor(time_to_cert_expires.seconds / 60 / 60),
            ))
        device_id = get_device_id()
        print('My WoTT ID is: {}'.format(device_id))

    print('Generating certificate...')
    gen_key = generate_cert(device_id)

    ca = get_ca_cert()
    if not ca:
        print('Unable to retrieve CA cert. Exiting.')
        exit(1)

    print('Submitting CSR...')

    if bootstrapping:
        crt = sign_cert(gen_key['csr'], device_id)
    else:
        crt = renew_cert(gen_key['csr'], device_id)

    print('Writing certificate and key to disk...')
    with open(CLIENT_CERT_PATH, 'w') as f:
        f.write(crt['crt'])

    with open(CA_CERT_PATH, 'w') as f:
        f.write(ca)

    with open(CLIENT_KEY_PATH, 'w') as f:
        f.write(gen_key['key'])

    with open(COMBINED_PEM_PATH, 'w') as f:
        f.write(gen_key['key'])
        f.write(crt['crt'])


if __name__ == "__main__":
    main()
