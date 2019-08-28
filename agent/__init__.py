import configparser
import os
import datetime
import platform
import socket
import netifaces
import json
import pwd
import glob
import logging
import logging.config
from math import floor
from sys import exit
from sys import stdout
from pathlib import Path

import requests
import pkg_resources
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytz

from agent import iptables_helper
from agent import journal_helper
from agent import rpi_helper
from agent import security_helper
from agent.executor import Locker
from agent.rpi_helper import Confinement, detect_confinement, detect_installation


CONFINEMENT = detect_confinement()
if CONFINEMENT == Confinement.SNAP:
    __version__ = os.environ['SNAP_VERSION']
else:
    try:
        __version__ = pkg_resources.get_distribution('wott-agent')
    except pkg_resources.DistributionNotFound:
        __version__ = (Path(__file__).parents[1] / 'VERSION').read_text().strip()


WOTT_ENDPOINT = os.getenv('WOTT_ENDPOINT', 'https://api.wott.io')
MTLS_ENDPOINT = WOTT_ENDPOINT.replace('api', 'mtls')
DASH_ENDPOINT = WOTT_ENDPOINT.replace('api', 'dash')
DASH_DEV_PORT = 8000
WOTT_DEV_PORT = 8001
MTLS_DEV_PORT = 8002
CONFINEMENT = detect_confinement()

CONFIG_PATH = os.getenv('CONFIG_PATH', '/opt/wott')
CERT_PATH = os.getenv('CERT_PATH', os.path.join(CONFIG_PATH, 'certs'))
CREDENTIALS_PATH = os.getenv('CREDENTIALS_PATH', os.path.join(CONFIG_PATH, 'credentials'))

CLIENT_CERT_PATH = os.path.join(CERT_PATH, 'client.crt')
CLIENT_KEY_PATH = os.path.join(CERT_PATH, 'client.key')
CA_CERT_PATH = os.path.join(CERT_PATH, 'ca.crt')
COMBINED_PEM_PATH = os.path.join(CERT_PATH, 'combined.pem')
INI_PATH = os.path.join(CONFIG_PATH, 'config.ini')
SECRET_DEV_METADATA_PATH = os.path.join(CONFIG_PATH, 'device_metadata.json')

if not os.path.isdir(CONFIG_PATH):
    os.makedirs(CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o711)

# This needs to be adjusted once we have
# changed the certificate life span from 7 days.
RENEWAL_THRESHOLD = 3

logger = logging.getLogger('agent')


def is_bootstrapping():
    # Create path if it doesn't exist
    if not os.path.isdir(CERT_PATH):
        os.makedirs(CERT_PATH)
    os.chmod(CERT_PATH, 0o711)

    client_cert = Path(CLIENT_CERT_PATH)

    if not client_cert.is_file():
        logger.warning('No certificate found on disk.')
        return True

    # Make sure there is no empty cert on disk
    if os.path.getsize(CLIENT_CERT_PATH) == 0:
        logger.warning('Certificate found but it is broken')
        return True

    return False


def can_read_cert():
    if not os.access(CLIENT_CERT_PATH, os.R_OK):
        logger.error('Permission denied when trying to read the certificate file.')
        exit(1)

    if not os.access(CLIENT_KEY_PATH, os.R_OK):
        logger.error('Permission denied when trying to read the key file.')
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


def generate_device_id():
    """
    Device ID is generated remotely.
    """
    device_id_request = requests.get(
        '{}/v0.2/generate-id'.format(WOTT_ENDPOINT)
    ).json()

    logger.debug("[RECEIVED] Generate Device ID: {}".format(device_id_request))

    return device_id_request['device_id']


def get_device_id(dev=False):
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

    logger.debug("[RECEIVED] Get CA Cert: {}".format(ca.status_code))
    logger.debug("[RECEIVED] Get CA Cert: {}".format(ca.content))

    if not ca.ok:
        logger.error('Failed to get CA...')
        logger.error(ca.status_code)
        logger.error(ca.content)
        return

    return ca.json()['ca_bundle']


def get_mtls_header(dev=False):
    return {
        'SSL-CLIENT-SUBJECT-DN': 'CN=' + get_device_id(),
        'SSL-CLIENT-VERIFY': 'SUCCESS'
    } if dev else {}


def req_error_log(req_type, requester, response, log_on_ok=False, caller=''):
    """
    logs error of mtls_request functions
    :param req_type: 'GET', 'POST', ...
    :param requester: requester id for message, if None then request_url string used
    :param response:  request response
    :param log_on_ok: if True then debug log message even if response.ok
    :param caller: caller string id
    :return: None
    """

    if log_on_ok or not response.ok:
        logger.debug("{} :: [RECEIVED] {} {}: {}".format(caller, requester, req_type, response.status_code))
        logger.debug("{} :: [RECEIVED] {} {}: {}".format(caller, requester, req_type, response.content))


def mtls_request(method, url, dev=False, requester_name=None, log_on_ok=False, return_exception=False, **kwargs):
    """
    MTLS  Request.request wrapper function.
    :param method = 'get,'put,'post','delete','patch','head','options'
    :param url: request url string (without endpoint)
    :param dev: if true use dev endpoint and dev headers
    :param requester_name: displayed requester id for error messages
    :param log_on_ok: if true then log debug message even if response.ok
    :param return_exception: if true, then returns tuple ( response, None ) or (None, RequestException)
    :return: response or None (if there was exception raised), or tuple (see above, return_exception)
    """
    try:
        r = requests.request(
            method,
            '{}/v0.2/{}'.format(MTLS_ENDPOINT, url),
            cert=(CLIENT_CERT_PATH, CLIENT_KEY_PATH),
            headers=get_mtls_header(dev=dev),
            **kwargs
        )

        if not requester_name:
            requester_name = "({})".format(url)

        req_error_log(method.upper(), requester_name, r, log_on_ok=log_on_ok, caller='mtls_request')
        if return_exception:
            return r, None
        else:
            return r

    except requests.exceptions.RequestException as e:
        logger.exception("mtls_request :: rises exception:")
        if return_exception:
            return None, e
        else:
            return None


def try_enroll_in_operation_mode(device_id, dev):
    enroll_token = get_enroll_token()
    if enroll_token is None:
        return
    logger.info("Enroll token found. Trying to automatically enroll the device.")

    setup_endpoints(dev)
    response = mtls_request('get', 'claimed', dev=dev, requester_name="Get Device Claim Info")
    if response is None or not response.ok:
        logger.error('Did not manage to get claim info from the server.')
        return
    logger.debug("[RECEIVED] Get Device Claim Info: {}".format(response))
    claim_info = response.json()
    if claim_info['claimed']:
        logger.info('The device is already claimed. No enrolling required.')
    else:
        claim_token = claim_info['claim_token']
        if not enroll_device(enroll_token, claim_token, device_id):
            logger.error('Device enrolling failed. Will try next time.')
            return

    logger.info("Update config...")
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    config.remove_option('DEFAULT', 'enroll_token')
    with open(INI_PATH, 'w') as configfile:
        config.write(configfile)
    os.chmod(INI_PATH, 0o600)


def get_claim_token(dev=False):

    setup_endpoints(dev)
    can_read_cert()

    response = mtls_request('get', 'claimed', dev=dev, requester_name="Get Device Claim Info")
    if response is None or not response.ok:
        logger.error('Did not manage to get claim info from the server.')
        exit(2)

    logger.debug("[RECEIVED] Get Device Claim Info: {}".format(response))

    claim_info = response.json()
    if claim_info['claimed']:
        logger.error('The device is already claimed.')
        exit(1)
    return claim_info['claim_token']


def get_fallback_token():
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    return config['DEFAULT'].get('fallback_token')


def get_ini_log_level():
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    return config['DEFAULT'].get('log_level')


def get_ini_log_file():
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    return config['DEFAULT'].get('log_file')


def get_enroll_token():
    config = configparser.ConfigParser()
    config.read(INI_PATH)
    return config['DEFAULT'].get('enroll_token')


def get_claim_url(dev=False):
    return '{WOTT_ENDPOINT}/claim-device?device_id={device_id}&claim_token={claim_token}'.format(
        WOTT_ENDPOINT=DASH_ENDPOINT,
        device_id=get_device_id(),
        claim_token=get_claim_token(dev)
    )


def get_uptime():
    """
    Returns the uptime in seconds.
    """

    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])

    return uptime_seconds


def get_open_ports(dev=False):
    connections, ports = security_helper.netstat_scan()
    return ports


def send_ping(dev=False):
    can_read_cert()

    ping = mtls_request('get', 'ping', dev=dev, requester_name="Ping", log_on_ok=True)

    if ping is None or not ping.ok:
        logger.error('Ping failed.')
        return

    connections, ports = security_helper.netstat_scan()
    payload = {
        'device_operating_system_version': platform.release(),
        'fqdn': socket.getfqdn(),
        'ipv4_address': get_primary_ip(),
        'uptime': get_uptime(),
        'agent_version': str(__version__),
        'confinement': CONFINEMENT.name,
        'installation': detect_installation().name
    }

    # Things we can't do within a Snap or Docker
    if CONFINEMENT not in (Confinement.SNAP, Confinement.DOCKER, Confinement.BALENA):
        payload.update({
            'processes': security_helper.process_scan(),
            'logins': journal_helper.logins_last_hour(),
            'default_password': security_helper.check_for_default_passwords(CONFIG_PATH)
        })

    # Things we cannot do in Docker
    if CONFINEMENT not in (Confinement.DOCKER, Confinement.BALENA):
        blocklist = ping.json()
        iptables_helper.block(blocklist)

        payload.update({
            'selinux_status': security_helper.selinux_status(),
            'app_armor_enabled': security_helper.is_app_armor_enabled(),
            'firewall_rules': iptables_helper.dump(),
            'scan_info': ports,
            'netstat': connections
        })

    rpi_metadata = rpi_helper.detect_raspberry_pi()
    if rpi_metadata['is_raspberry_pi']:
        payload.update({
            'device_manufacturer': 'Raspberry Pi',
            'device_model': rpi_metadata['hardware_model'],
        })

    logger.debug("[GATHER] POST Ping: {}".format(payload))

    ping = mtls_request('post', 'ping', json=payload, dev=dev, requester_name="Ping", log_on_ok=True)

    if ping is None or not ping.ok:
        logger.error('Ping failed.')
        return


def say_hello(dev=False):
    hello = mtls_request('get', 'hello', dev=dev, requester_name='Hello')
    if hello is None or not hello.ok:
        logger.error('Hello failed.')
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
        logger.error('Failed to submit CSR...')
        req_error_log('post', 'Sign Cert', crt_req, caller='sign_cert')

    res = crt_req.json()
    return {
        'crt': res['certificate'],
        'claim_token': res['claim_token'],
        'fallback_token': res['fallback_token'],
        'claimed': False
    }


def renew_cert(csr, device_id):
    """
    This is the renewal function. We need to use the existing certificate to
    verify ourselves in order to get a renewed certificate
    """

    logger.info('Attempting to renew certificate...')
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

    crt_req = mtls_request('post', 'sign-csr', False, 'Renew Cert', json=payload)

    if crt_req is None or not crt_req.ok:
        logger.error('Failed to submit CSR...')
        return

    res = crt_req.json()
    return {
        'crt': res['certificate'],
        'claim_token': res['claim_token'],
        'fallback_token': res['fallback_token'],
        'claimed': res['claimed'],
    }


def renew_expired_cert(csr, device_id):
    """
    This is the renewal function. We need to use the existing certificate to
    verify ourselves in order to get a renewed certificate
    """

    logger.info('Attempting to renew expired certificate...')
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
        logger.error('Failed to submit CSR...')
        req_error_log('post', 'Renew expired Cert', crt_req)
        return

    res = crt_req.json()
    return {
        'crt': res['certificate'],
        'claim_token': res['claim_token'],
        'fallback_token': res['fallback_token'],
        'claimed': res['claimed'],
    }


def setup_endpoints(dev):
    if dev:
        global WOTT_ENDPOINT, MTLS_ENDPOINT, DASH_ENDPOINT
        endpoint = os.getenv('WOTT_ENDPOINT', 'http://localhost')
        DASH_ENDPOINT = endpoint + ':' + str(DASH_DEV_PORT)
        WOTT_ENDPOINT = endpoint + ':' + str(WOTT_DEV_PORT) + '/api'
        MTLS_ENDPOINT = endpoint + ':' + str(MTLS_DEV_PORT) + '/api'

    logger.debug(
        "\nDASH_ENDPOINT: %s\nWOTT_ENDPOINT: %s\nMTLS_ENDPOINT: %s",
        DASH_ENDPOINT, WOTT_ENDPOINT, MTLS_ENDPOINT
    )


def fetch_device_metadata(dev, logger=logger):

    with Locker('dev.metadata'):
        setup_endpoints(dev)
        logger.info('Fetching device metadata...')
        can_read_cert()

        dev_md_req = mtls_request('get', 'device-metadata', dev=dev, requester_name="Fetching device metadata")
        if dev_md_req is None or not dev_md_req.ok:
            logger.error('Fetching failed.')
            return

        metadata = dev_md_req.json()

        logger.info('metadata retrieved.')

        if os.path.exists(SECRET_DEV_METADATA_PATH) and not os.path.isfile(SECRET_DEV_METADATA_PATH):
            logger.error("Error: The filesystem object '{}' is not a file. Looks like a break-in attempt.".format(
                SECRET_DEV_METADATA_PATH
            ))
            exit(1)

        with open(SECRET_DEV_METADATA_PATH, "w") as outfile:
            json.dump(metadata, outfile, indent=4)
        os.chmod(SECRET_DEV_METADATA_PATH, 0o600)
        logger.info('metadata stored.')


def fetch_credentials(dev, logger=logger):

    def clear_credentials(path):
        files = glob.glob(os.path.join(path, '**/*.json'), recursive=True)
        for file in files:
            os.remove(os.path.join(path, file))
            logger.debug("remove...{}".format(file))

    with Locker('credentials'):
        setup_endpoints(dev)
        logger.info('Fetching credentials...')
        can_read_cert()

        credentials_req = mtls_request('get', 'credentials', dev=dev, requester_name="Fetch credentials")
        if credentials_req is None or not credentials_req.ok:
            logger.error('Fetching failed.')
            return
        credentials = credentials_req.json()

        logger.info('Credentials retrieved.')

        if not os.path.exists(CREDENTIALS_PATH):
            os.mkdir(CREDENTIALS_PATH, 0o711)
        else:
            os.chmod(CREDENTIALS_PATH, 0o711)

        if not os.path.isdir(CREDENTIALS_PATH):
            logger.error("There is file named as our credentials dir(%s), that's strange...", CREDENTIALS_PATH)
            exit(1)

        clear_credentials(CREDENTIALS_PATH)

        # group received credentials, by linux_user, name
        credentials_grouped = {}
        for cred in credentials:
            name = cred['name']
            owner = cred['linux_user'] if 'linux_user' in cred else ''
            if owner not in credentials_grouped:
                credentials_grouped[owner] = {}
            if name not in credentials_grouped[owner]:
                credentials_grouped[owner][name] = cred['data']
            else:
                logger.error("Duplicated owner/name combination for credentials ({}/{}). Skipped.".format(owner, name))

        root_pw = pwd.getpwnam("root")

        for owner in credentials_grouped:

            pw = root_pw  # if no owner, use 'root'
            if owner:
                try:
                    pw = pwd.getpwnam(owner)
                except KeyError:
                    logger.warning("There are credentials with wrong owner ({}). Skipped.".format(owner))
                    continue

            uid = pw.pw_uid
            gid = pw.pw_gid

            owner_path = CREDENTIALS_PATH if not owner else os.path.join(CREDENTIALS_PATH, owner)

            if owner and not os.path.isdir(owner_path):
                if os.path.exists(owner_path):
                    logger.error(
                        "There is a file with name of system user in credentials directory ({}).".format(owner_path)
                    )
                    exit(1)
                os.mkdir(owner_path, 0o700)
            os.chown(owner_path, uid, gid)  # update ownership if user existence in system changed

            for name in credentials_grouped[owner]:
                credential_file_path = os.path.join(owner_path, "{}.json".format(name))
                file_credentials = credentials_grouped[owner][name]

                logger.debug('Store credentials to {}'.format(credential_file_path))

                with open(credential_file_path, 'w') as outfile:
                    json.dump(file_credentials, outfile, indent=4)

                os.chmod(credential_file_path, 0o400)
                os.chown(credential_file_path, uid, gid)


def write_metadata(data, rewrite_file):
    metadata_path = Path(CONFIG_PATH) / 'metadata.json'
    if rewrite_file or not metadata_path.is_file():
        with metadata_path.open('w') as metadata_file:
            json.dump(data, metadata_file)
    metadata_path.chmod(0o644)


def _log_request_errors(req):
    errors = req.json()
    logger.error("Code:{}, Reason:{}".format(req.status_code, req.reason))
    for key in errors:
        key_errors = errors[key]
        if isinstance(key_errors, list):
            for msg in key_errors:
                logger.error("{} : {}".format(key, msg))
        else:
            logger.error("{} : {}".format(key, key_errors))


def enroll_device(enroll_token, claim_token, device_id):
    """
    Enroll device using enroll_token to authorize
    :param enroll_token: enroll pairing key
    :param claim_token: claim token
    :param device_id: device id
    :return: True if enrolled successfully, otherwise return False
    """
    payload = {
        'key': enroll_token,
        'claim_token': claim_token,
        'device_id': device_id
    }
    try:
        enroll_req = requests.post(
            '{}/v0.2/enroll-device'.format(WOTT_ENDPOINT),
            json=payload
        )
        if not enroll_req.ok:
            logger.error('Failed to enroll device...')
            _log_request_errors(enroll_req)
            req_error_log('post', 'Enroll by token', enroll_req, caller='enroll-device')
            return False
        else:
            logger.info('Device {} enrolled successfully.'.format(device_id))
            return True
    except requests.exceptions.RequestException:
        logger.exception("enroll_device :: rises exception:")
        return False


def run(ping=True, dev=False, logger=logger):

    with Locker('ping'):
        setup_endpoints(dev)
        bootstrapping = is_bootstrapping()

        if bootstrapping:
            device_id = generate_device_id()
            logger.info('Got WoTT ID: {}'.format(device_id))
            write_metadata({'device_id': device_id}, rewrite_file=True)
        else:
            device_id = get_device_id()
            try_enroll_in_operation_mode(device_id=device_id, dev=dev)
            write_metadata({'device_id': device_id}, rewrite_file=False)
            if not time_for_certificate_renewal() and not is_certificate_expired():
                if ping:
                    send_ping(dev=dev)
                    time_to_cert_expires = get_certificate_expiration_date() - datetime.datetime.now(datetime.timezone.utc)
                    logger.info(
                        "Certificate expires in {} days and {} hours. No need for renewal."
                        "Renewal threshold is set to {} days.".format(
                            time_to_cert_expires.days,
                            floor(time_to_cert_expires.seconds / 60 / 60),
                            RENEWAL_THRESHOLD,
                        )
                    )
                    exit(0)
                else:
                    return
            logger.info('My WoTT ID is: {}'.format(device_id))

        logger.info('Generating certificate...')
        gen_key = generate_cert(device_id)

        ca = get_ca_cert()
        if not ca:
            logger.error('Unable to retrieve CA cert. Exiting.')
            exit(1)

        logger.info('Submitting CSR...')

        enroll_token = None
        if bootstrapping:
            crt = sign_cert(gen_key['csr'], device_id)
            enroll_token = get_enroll_token()
            if enroll_token is not None:
                logger.info('Device enrollment token found...')
        elif is_certificate_expired():
            crt = renew_expired_cert(gen_key['csr'], device_id)
        else:
            crt = renew_cert(gen_key['csr'], device_id)

        if not crt:
            logger.error('Unable to sign CSR. Exiting.')
            exit(1)

        if enroll_token is None:
            logger.info('Got Claim Token: {}'.format(crt['claim_token']))
            logger.info(
                'Claim your device: {WOTT_ENDPOINT}/claim-device?device_id={device_id}&claim_token={claim_token}'.format(
                    WOTT_ENDPOINT=DASH_ENDPOINT,
                    device_id=device_id,
                    claim_token=crt['claim_token']
                )
            )

        logger.info('Writing certificate and key to disk...')
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

        send_ping(dev=dev)

        if enroll_token is not None:
            logger.info('Enroll device by token...')
            if enroll_device(enroll_token, crt['claim_token'], device_id):
                enroll_token = None

        logger.info("Writing config...")
        config = configparser.ConfigParser()
        config['DEFAULT'] = {'fallback_token': crt['fallback_token']}
        if enroll_token is not None:
            config['DEFAULT']['enroll_token'] = enroll_token  # if enroll fails, store enroll token for next run
        with open(INI_PATH, 'w') as configfile:
            config.write(configfile)
        os.chmod(INI_PATH, 0o600)


def setup_logging(level=None, log_format="%(message)s", daemon=True):
    """
    Setup logging configuration
    if there is `log_level` item in wott-agent `config.ini` it would be used as actual log level
    otherwise used value of level parameter
    """

    log_level = level if level is not None else logging.INFO
    ini_level = get_ini_log_level()
    if ini_level is not None and isinstance(ini_level, str):
        ini_level = ini_level.upper()
        if ini_level in ['CRITICAL', 'ERROR', 'WARN', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']:
            if level is None:
                log_level = ini_level

    filename = get_ini_log_file()
    handlers = []
    if filename is not None and filename != 'stdout':
        file_handler = logging.FileHandler(filename=filename)
        handlers.append(file_handler)

    if filename is None or filename == 'stdout' or not daemon:
        stdout_handler = logging.StreamHandler(stdout)
        handlers.append(stdout_handler)

    if not daemon:
        stdout_handler.setFormatter(logging.Formatter("%(message)s"))

    logging.basicConfig(level=log_level, format=log_format, handlers=handlers)

    logging.getLogger('agent').setLevel(log_level)
    logging.getLogger('agent.iptables_helper').setLevel(log_level)
    logging.getLogger('agent.executor').setLevel(log_level)
