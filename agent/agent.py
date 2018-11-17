import cfssl
import sh
import json
import sys
import hashlib
from datetime import datetime, timedelta
import OpenSSL.crypto


CFSSL_SERVER = '192.168.202.52'
CFSSL_PORT = 8888
CERT_PATH = '/opt/wott/ssl'
RENEWAL_THRESHOLD = 15


def time_for_certificate_renewal():
    """ Check if it's time for certificate renewal """

    with open('client.crt', 'rt') as f:
        cert = OpenSSL.crypto.load_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                f.read()
                )
        expiration_date = cert.get_notAfter()

    # Ugly workaround for date parsing
    cert_expiration_time = datetime.strptime(expiration_date[0:-2], '%Y%m%d%H%M%S')
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

    hostname = hashlib.sha512('{}-{}-{}'.format(serial, revision, hardware)).hexdigest()[0:32]

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

    crt_req = cf.sign(certificate_request=csr, hosts=['{}'.format(device_uuid)])
    ca = cf.info(label='primary')

    return {'crt': crt_req, 'ca': ca['certificate']}


def main():
    if not time_for_certificate_renewal():
        print("Certificate is valid. No need for renewal.")
        sys.exit(0)

    device_uuid = generate_uuid()
    gen_key = generate_cert(device_uuid)
    crt = sign_cert(gen_key['csr'], device_uuid)

    with open('client.crt', 'w') as f:
        f.write(crt['crt'])

    with open('ca.crt', 'w') as f:
        f.write(crt['ca'])

    with open('client.key', 'w') as f:
        f.write(gen_key['key'])


if __name__ == "__main__":
    main()
