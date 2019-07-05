import pytz
import json
import requests
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from google.oauth2 import service_account
from googleapiclient import discovery

RENEWAL_THRESHOLD = 3

PROJECT_ID = ""
CLOUD_REGION = ""
REGISTRY_ID = ""
SERVICE_ACCOUNT_JSON = 'user_secret.json'

REMOVE_EXPIRED_CERTS = True

# wott api token
token = ''  



def get_client(service_account_json):
    """Returns an authorized API client by discovering the IoT API and creating
    a service object using the service account credentials JSON."""
    api_scopes = ['https://www.googleapis.com/auth/cloud-platform']
    api_version = 'v1'
    discovery_api = 'https://cloudiot.googleapis.com/$discovery/rest'
    service_name = 'cloudiotcore'

    credentials = service_account.Credentials.from_service_account_file(
            service_account_json)
    scoped_credentials = credentials.with_scopes(api_scopes)

    discovery_url = '{}?version={}'.format(
            discovery_api, api_version)

    return discovery.build(
            service_name,
            api_version,
            discoveryServiceUrl=discovery_url,
            credentials=scoped_credentials)

def enroll_device(client, registry_path, device_id, certificate):

    # Note: You can have multiple credentials associated with a device.
    device_template = {
        'id': device_id,
        'credentials': [{
            'publicKey': {
                'format': 'ES256_X509_PEM',
                'key': certificate
            }
        }]
    }

    devices = client.projects().locations().registries().devices()
    return devices.create(parent=registry_path, body=device_template).execute()


def patch_device(client, registry_path, device_id, credentials):
    print('Patch device with ES256-X509-PEM certificate')

    patch = {
        'credentials': credentials
    }

    device_name = '{}/devices/{}'.format(registry_path, device_id)

    return client.projects().locations().registries().devices().patch(
        name=device_name, updateMask='credentials', body=patch).execute()


def get_device_list(client, registry_path):
    print('Listing devices')
    devices = client.projects().locations().registries().devices(
    ).list(parent=registry_path).execute().get('devices', [])

    for device in devices:
        print('Device: {} : {}'.format(
            device.get('numId'),
            device.get('id')))

    return devices


def get_wott_device_list(token):
    try:
        req = requests.get("https://api.wott.io/v0.2/list-devices",
                           headers={"Authorization": "Token {}".format(token), "Content-Type": "application/json"})

    except requests.exceptions.RequestException as e:
        print("{}".format(e))
        return None
    return req


def get_wott_device_cert(device_id):
    try:
        req = requests.get('https://api.wott.io/v0.2/device-cert/{}'.format(device_id))

    except requests.exceptions.RequestException as e:
        print("{}".format(e))
        return None
    return req


def get_certificate_expiration_date(cert_string):
    """
    Returns the expiration date of the certificate.
    """

    cert = x509.load_pem_x509_certificate(
            cert_string, default_backend()
        )

    return cert.not_valid_after.replace(tzinfo=pytz.utc)


def is_certificate_expired(cert_string):
    return datetime.datetime.now(datetime.timezone.utc) > get_certificate_expiration_date(cert_string)


def main():
    project_id = PROJECT_ID
    cloud_region = CLOUD_REGION
    registry_id = REGISTRY_ID
    service_account_json = SERVICE_ACCOUNT_JSON

    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
        project_id, cloud_region, registry_id)

    client = get_client(service_account_json)

    dev_list_resp = get_wott_device_list(token)
    if dev_list_resp is None or not dev_list_resp.ok:
        print("Could not get device list from WoTT server")
        exit(1)

    wott_dev_list = dev_list_resp.json()

    devices = {}

    for device in wott_dev_list:
        cert = None
        device_id = device['device']['device_id']
        cert_resp = get_wott_device_cert(device_id)
        if cert_resp is None or not cert_resp.ok:
            print("Could not get device cert for device {} from WoTT server".format(device['device']['name']))
        else:
            cert = cert_resp.text

        gcloud_dev_id = 'a-'+device_id if device_id[:1].isdigit() else device_id
        devices[device_id] = {'wott': device, 'cert': cert, 'gc_id': gcloud_dev_id, 'done': False}

    gc_dev_list = get_device_list(client, registry_name)

    for device in gc_dev_list:
        wott_dev_id = device.get('id')
        if wott_dev_id[:2] == 'a-':
            wott_dev_id = wott_dev_id[2:]

        if wott_dev_id in devices:
            devices[wott_dev_id]['done'] = True   # mark that this device was found and processed

            credentials = device.get('credentials')
            if credentials is None:
                credentials = []

            skip = False
            for idx, cred in enumerate(credentials):
                if cred['publicKey']['key'] == devices[wott_dev_id]['cert']: # cert is already here, skip that device
                    skip = True
                    break

            if REMOVE_EXPIRED_CERTS:
                credentials = [cred for cred in credentials if not is_certificate_expired(cred['publicKey']['key'])]

            if skip:
                continue

            credentials.append(
                {
                    'publicKey': {
                        'format': 'ES256_X509_PEM',
                        'key': devices[wott_dev_id]['cert']
                    }
                }
            )
            patch_device(client, registry_name, device.get('id'), credentials)
            print("patch {} with new cert".format(devices[wott_dev_id]['wott']['device']['name']))

    for _, device in devices.items():
        if not device['done']:  # if this device was not processed in previous cycle, then it is new one
            enroll_device(client, registry_name, device['gc_id'], device['cert'])
            print("Enroll {} as {}".format(device['wott']['device']['name'], device['gc_id']))

    print("{}".format(json.dumps(devices, indent=4)))


if __name__ == '__main__':
    main()

