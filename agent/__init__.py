import os
import requests
import datetime
import pytz
import platform
import socket
import netifaces

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from math import floor
from pathlib import Path
from sys import exit

WOTT_ENDPOINT = os.getenv('WOTT_ENDPOINT', 'https://api.wott.io')
MTLS_ENDPOINT = WOTT_ENDPOINT.replace('api', 'mtls')

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
    # Create path if it doesn't exist
    if not os.path.isdir(CERT_PATH):
        os.makedirs(CERT_PATH)
        os.chmod(CERT_PATH, 0o700)

    client_cert = Path(CLIENT_CERT_PATH)

    if not client_cert.is_file():
        print('No certificate found on disk.')
        return True

    # Make sure there is no empty cert on disk
    if os.path.getsize(CLIENT_CERT_PATH) == 0:
        print('Certificate found but it is broken')
        return True

    return False


def can_read_cert():
    if not os.access(CLIENT_CERT_PATH, os.R_OK):
        print('Permission denied when trying to read the certificate file.')
        exit(1)

    if not os.access(CLIENT_KEY_PATH, os.R_OK):
        print('Permission denied when trying to read the key file.')
        exit(1)


def get_primary_ip():
    try:
        primary_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        addrs = netifaces.ifaddresses(primary_interface)
        return addrs[netifaces.AF_INET][0]['addr']
    except:
        return None


def get_certificate_expiration_date():
    """
    Returns the expiration date of the certificate.
    """

    can_read_cert()

    with open(CLIENT_CERT_PATH, 'r') as f:
        cert = x509.load_pem_x509_certificate(
            f.read().encode(), default_backend()
        )

    return cert.not_valid_after.replace(tzinfo=pytz.utc)


def time_for_certificate_renewal():
    """ Check if it's time for certificate renewal """
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=RENEWAL_THRESHOLD) > get_certificate_expiration_date()


def generate_device_id():
    """
    Device ID is generated remotely.
    """
    device_id_request = requests.get(
            '{}/v0.2/generate-id'.format(WOTT_ENDPOINT)
            ).json()
    return device_id_request['device_id']


def get_device_id():
    """
    Returns the WoTT Device ID (i.e. fqdn) by reading the first subject from
    the certificate on disk.
    """

    can_read_cert()

    with open(CLIENT_CERT_PATH, 'r') as f:
        cert = x509.load_pem_x509_certificate(
            f.read().encode(), default_backend()
        )

    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def generate_cert(device_id):
    private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )
    builder = x509.CertificateSigningRequestBuilder()

    builder = builder.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'{}'.format(device_id)),
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'UK'),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'London'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Web of Trusted Things, Ltd'),
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
    ca = requests.get('{}/v0.2/ca-bundle'.format(WOTT_ENDPOINT))

    if not ca.ok:
        print('Failed to get CA...')
        print(ca.status_code)
        print(ca.content)
        return

    return ca.json()['ca_bundle']


def send_ping():
    can_read_cert()

    payload = {
        'device_operating_system_version': platform.release(),
        'fqdn': socket.getfqdn(),
        'ipv4_address': get_primary_ip(),
    }

    ping = requests.POST(
        '{}/v0.2/ping'.format(MTLS_ENDPOINT),
        verify=CA_CERT_PATH,
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
        json=payload
    )

    if not ping.ok:
        print('Ping failed.')


def say_hello():
    hello = requests.get(
        '{}/v0.2/hello'.format(MTLS_ENDPOINT),
        verify=CA_CERT_PATH,
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
    )
    if not hello.ok:
        print('Hello failed.')
    return hello.json()


def sign_cert(csr, device_id):
    """
    This is the function for the initial certificate generation.
    This is only valid for the first time. Future renewals require the
    existing certificate to renew.
    """

    payload = {
            'csr': csr,
            'device_id': device_id,
            'device_architecture': platform.machine(),
            'device_operating_system': platform.system(),
            'device_operating_system_version': platform.release(),
            'fqdn': socket.getfqdn(),
            'ipv4_address': get_primary_ip(),
    }

    crt_req = requests.post(
            '{}/v0.2/sign-csr'.format(WOTT_ENDPOINT),
            json=payload
            )

    if not crt_req.ok:
        print('Failed to submit CSR...')
        print(crt_req.status_code)
        print(crt_req.content)
        return

    return {
        'crt': crt_req.json()['certificate'],
        'claim_token': crt_req.json()['claim_token']
    }


def renew_cert(csr, device_id):
    """
    This is the renewal function. We need to use the existing certificate to
    verify ourselves in order to get a renewed certificate
    """

    print('Attempting to renew certificate...')
    can_read_cert()

    payload = {
            'csr': csr,
            'device_id': device_id,
            'device_architecture': platform.system(),
            'device_operating_system': platform.system(),
            'device_operating_system_version': platform.release(),
            'fqdn': socket.getfqdn()
            'ipv4_address': get_primary_ip()
            }

    crt_req = requests.post(
        '{}/v0.2/sign-csr'.format(MTLS_ENDPOINT),
        verify=CA_CERT_PATH,
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
        json=payload
        )

    if not crt_req.ok:
        print('Failed to submit CSR...')
        print(crt_req.status_code)
        print(crt_req.content)
        return

    return {
        'crt': crt_req.json()['certificate'],
        'claim_token': crt_req.json()['claim_token']
    }


def main():
    bootstrapping = is_bootstrapping()

    if bootstrapping:
        device_id = generate_device_id()
        print('Got WoTT ID: {}'.format(device_id))
    else:
        if not time_for_certificate_renewal():
            send_ping()
            time_to_cert_expires = get_certificate_expiration_date() - datetime.datetime.now(datetime.timezone.utc)
            print("Certificate expires in {} days and {} hours. No need for renewal. Renewal threshold is set to {} days.".format(
                time_to_cert_expires.days,
                floor(time_to_cert_expires.seconds / 60 / 60),
                RENEWAL_THRESHOLD,
            ))
            exit(0)
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

    if not crt:
        print('Unable to sign CSR. Exiting.')
        exit(1)

    print('Got Claim Token: {}'.format(crt['claim_token']))
    print('Writing certificate and key to disk...')
    with open(CLIENT_CERT_PATH, 'w') as f:
        f.write(crt['crt'])
    os.chmod(CLIENT_CERT_PATH, 0o644)

    with open(CA_CERT_PATH, 'w') as f:
        f.write(ca)
    os.chmod(CA_CERT_PATH, 0o644)

    with open(CLIENT_KEY_PATH, 'w') as f:
        f.write(gen_key['key'])
    os.chmod(CLIENT_KEY_PATH, 0o600)

    with open(COMBINED_PEM_PATH, 'w') as f:
        f.write(gen_key['key'])
        f.write(crt['crt'])
    os.chmod(COMBINED_PEM_PATH, 0o600)


if __name__ == "__main__":
    main()
