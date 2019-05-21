import configparser
import os
import requests
import datetime
import pytz
import platform
import socket
import netifaces

from agent import journal_helper
from agent import rpi_helper
from agent import security_helper
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
DASH_ENDPOINT = WOTT_ENDPOINT.replace('api', 'dash')
DASH_DEV_PORT = 8000
WOTT_DEV_PORT = 8001
MTLS_DEV_PORT = 8002

# Conditional handling for if we're running
# inside a Snap.
if os.getenv('SNAP_NAME'):
    CONFIG_PATH = CERT_PATH = os.getenv('SNAP_DATA')
else:
    CERT_PATH = os.getenv('CERT_PATH', '/opt/wott/certs')
    CONFIG_PATH = os.getenv('CERT_PATH', '/opt/wott')

# This needs to be adjusted once we have
# changed the certificate life span from 7 days.
RENEWAL_THRESHOLD = 3

CLIENT_CERT_PATH = os.path.join(CERT_PATH, 'client.crt')
CLIENT_KEY_PATH = os.path.join(CERT_PATH, 'client.key')
CA_CERT_PATH = os.path.join(CERT_PATH, 'ca.crt')
COMBINED_PEM_PATH = os.path.join(CERT_PATH, 'combined.pem')
INI_PATH = os.path.join(CONFIG_PATH, 'config.ini')
CREDS_PATH = os.path.join(CONFIG_PATH, 'creds.ini')


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
    except (OSError, KeyError):
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


def is_certificate_expired():
    return datetime.datetime.now(datetime.timezone.utc) > get_certificate_expiration_date()


def generate_device_id(debug=False):
    """
    Device ID is generated remotely.
    """
    device_id_request = requests.get(
        '{}/v0.2/generate-id'.format(WOTT_ENDPOINT)
    ).json()

    if debug:
        print("[RECEIVED] Generate Device ID: {}".format(device_id_request))

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


def get_ca_cert(debug=False):
    ca = requests.get('{}/v0.2/ca-bundle'.format(WOTT_ENDPOINT))

    if debug:
        print("[RECEIVED] Get CA Cert: {}".format(ca.status_code))
        print("[RECEIVED] Get CA Cert: {}".format(ca.content))

    if not ca.ok:
        print('Failed to get CA...')
        print(ca.status_code)
        print(ca.content)
        return

    return ca.json()['ca_bundle']


def get_claim_token():
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    return config['DEFAULT'].get('claim_token', None)


def get_fallback_token():
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    return config['DEFAULT'].get('fallback_token', None)


def get_claim_url():
    return '{WOTT_ENDPOINT}/claim-device?device_id={device_id}&claim_token={claim_token}'.format(
        WOTT_ENDPOINT=DASH_ENDPOINT,
        device_id=get_device_id(),
        claim_token=get_claim_token()
    )


def get_uptime():
    """
    Returns the uptime in seconds.
    """

    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])

    return uptime_seconds


def get_open_ports():
    connections, ports = security_helper.netstat_scan()
    return ports


def send_ping(debug=False, dev=False):
    can_read_cert()

    connections, ports = security_helper.netstat_scan()
    payload = {
        'device_operating_system_version': platform.release(),
        'fqdn': socket.getfqdn(),
        'ipv4_address': get_primary_ip(),
        'uptime': get_uptime(),
        'scan_info': ports,
        'netstat': connections,
        'processes': security_helper.process_scan(),
        'firewall_enabled': security_helper.is_firewall_enabled(),
        'firewall_rules': security_helper.get_firewall_rules(),
        'selinux_status': security_helper.selinux_status(),
        'app_armor_enabled': security_helper.is_app_armor_enabled(),
        'logins': journal_helper.logins_last_hour(),
        'default_password': security_helper.check_for_default_passwords(CONFIG_PATH)
    }

    rpi_metadata = rpi_helper.detect_raspberry_pi()
    if rpi_metadata['is_raspberry_pi']:
        payload['device_manufacturer'] = 'Raspberry Pi'
        payload['device_model'] = rpi_metadata['hardware_model']

    if debug:
        print("[GATHER] Ping: {}".format(payload))

    ping = requests.post(
        '{}/v0.2/ping'.format(MTLS_ENDPOINT),
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
        json=payload,
        headers={
            'SSL-CLIENT-SUBJECT-DN': 'CN=' + get_device_id(),
            'SSL-CLIENT-VERIFY': 'SUCCESS'
        } if dev else {}
    )

    if debug:
        print("[RECEIVED] Ping: {}".format(ping.status_code))
        print("[RECEIVED] Ping: {}".format(ping.content))

    if not ping.ok:
        print('Ping failed.')
        return

    pong = ping.json()
    security_helper.block_ports(pong.get('block_ports', {'tcp': [], 'udp': []}))
    security_helper.block_networks(pong.get('block_networks', []))


def say_hello():
    hello = requests.get(
        '{}/v0.2/hello'.format(MTLS_ENDPOINT),
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
    )
    if not hello.ok:
        print('Hello failed.')
    return hello.json()


def sign_cert(csr, device_id, debug=False):
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
        if debug:
            print("[RECEIVED] Sign Cert: {}".format(crt_req.status_code))
            print("[RECEIVED] Sign Cert: {}".format(crt_req.content))
        return

    res = crt_req.json()
    return {
        'crt': res['certificate'],
        'claim_token': res['claim_token'],
        'fallback_token': res['fallback_token']
    }


def renew_cert(csr, device_id, debug=False):
    """
    This is the renewal function. We need to use the existing certificate to
    verify ourselves in order to get a renewed certificate
    """

    print('Attempting to renew certificate...')
    can_read_cert()

    payload = {
        'csr': csr,
        'device_id': device_id,
        'device_architecture': platform.machine(),
        'device_operating_system': platform.system(),
        'device_operating_system_version': platform.release(),
        'fqdn': socket.getfqdn(),
        'ipv4_address': get_primary_ip()
    }

    crt_req = requests.post(
        '{}/v0.2/sign-csr'.format(MTLS_ENDPOINT),
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
        json=payload
    )

    if not crt_req.ok:
        print('Failed to submit CSR...')
        if debug:
            print("[RECEIVED] Renew Cert: {}".format(crt_req.status_code))
            print("[RECEIVED] Renew Cert: {}".format(crt_req.content))
        return

    res = crt_req.json()
    return {
        'crt': res['certificate'],
        'claim_token': res['claim_token'],
        'fallback_token': res['fallback_token']
    }


def renew_expired_cert(csr, device_id, debug=False):
    """
    This is the renewal function. We need to use the existing certificate to
    verify ourselves in order to get a renewed certificate
    """

    print('Attempting to renew expired certificate...')
    can_read_cert()

    payload = {
        'csr': csr,
        'device_id': device_id,
        'device_architecture': platform.machine(),
        'device_operating_system': platform.system(),
        'device_operating_system_version': platform.release(),
        'fqdn': socket.getfqdn(),
        'ipv4_address': get_primary_ip(),
        'fallback_token': get_fallback_token()
    }

    crt_req = requests.post(
        '{}/v0.2/sign-expired-csr'.format(WOTT_ENDPOINT),
        json=payload
    )

    if not crt_req.ok:
        print('Failed to submit CSR...')
        if debug:
            print("[RECEIVED] Renew expired Cert: {}".format(crt_req.status_code))
            print("[RECEIVED] Renew expired Cert: {}".format(crt_req.content))
        return

    res = crt_req.json()
    return {
        'crt': res['certificate'],
        'claim_token': res['claim_token'],
        'fallback_token': res['fallback_token']
    }


def fetch_creds(debug, dev):
    print('Fetching credentials...')
    can_read_cert()

    creds_req = requests.get(
        '{}/v0.2/creds'.format(MTLS_ENDPOINT),
        cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
        headers={
            'SSL-CLIENT-SUBJECT-DN': 'CN=' + get_device_id(),
            'SSL-CLIENT-VERIFY': 'SUCCESS'
        } if dev else {}
    )
    if not creds_req.ok:
        print('Fetching failed.')
        if debug:
            print("[RECEIVED] Fetch creds: code {}".format(creds_req.status_code))
            print("[RECEIVED] Fetch creds: {}".format(creds_req.content))
    creds = creds_req.json()

    print('Credentials retreived.')
    if debug:
        print('Creds: {}'.format(creds))

    config = configparser.ConfigParser()
    with open(CREDS_PATH, 'w') as configfile:
        config.write(configfile)
    os.chmod(CREDS_PATH, 0o600)


def run(ping=True, debug=False, dev=False):
    if dev:
        global WOTT_ENDPOINT, MTLS_ENDPOINT, DASH_ENDPOINT
        endpoint = os.getenv('WOTT_ENDPOINT', 'http://localhost')
        DASH_ENDPOINT = endpoint + ':' + str(DASH_DEV_PORT)
        WOTT_ENDPOINT = endpoint + ':' + str(WOTT_DEV_PORT) + '/api'
        MTLS_ENDPOINT = endpoint + ':' + str(MTLS_DEV_PORT) + '/api'

    bootstrapping = is_bootstrapping()

    if bootstrapping:
        device_id = generate_device_id(debug=debug)
        print('Got WoTT ID: {}'.format(device_id))
    else:
        if not time_for_certificate_renewal() and not is_certificate_expired():
            if ping:
                send_ping(debug=debug, dev=dev)
                time_to_cert_expires = get_certificate_expiration_date() - datetime.datetime.now(datetime.timezone.utc)
                print("Certificate expires in {} days and {} hours. No need for renewal. Renewal threshold is set to {} days.".format(
                    time_to_cert_expires.days,
                    floor(time_to_cert_expires.seconds / 60 / 60),
                    RENEWAL_THRESHOLD,
                ))
                exit(0)
            else:
                return
        device_id = get_device_id()
        print('My WoTT ID is: {}'.format(device_id))

    print('Generating certificate...')
    gen_key = generate_cert(device_id)

    ca = get_ca_cert(debug=debug)
    if not ca:
        print('Unable to retrieve CA cert. Exiting.')
        exit(1)

    print('Submitting CSR...')

    if bootstrapping:
        crt = sign_cert(gen_key['csr'], device_id, debug=debug)
    elif is_certificate_expired():
        crt = renew_expired_cert(gen_key['csr'], device_id, debug=debug)
    else:
        crt = renew_cert(gen_key['csr'], device_id, debug=debug)

    if not crt:
        print('Unable to sign CSR. Exiting.')
        exit(1)

    print('Got Claim Token: {}'.format(crt['claim_token']))
    print('Claim your device: {WOTT_ENDPOINT}/claim-device?device_id={device_id}&claim_token={claim_token}'.format(
        WOTT_ENDPOINT=DASH_ENDPOINT,
        device_id=device_id,
        claim_token=crt['claim_token']
    )
    )
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

    print("Writing config...")
    config = configparser.ConfigParser()
    config['DEFAULT'] = {
        'claim_token': crt['claim_token'],
        'fallback_token': crt['fallback_token']
    }
    with open(INI_PATH, 'w') as configfile:
        config.write(configfile)
    os.chmod(INI_PATH, 0o600)

    send_ping(debug=debug, dev=dev)
