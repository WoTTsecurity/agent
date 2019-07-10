import pytz
import json
import requests
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from google.oauth2 import service_account
from googleapiclient import discovery
from googleapiclient.errors import HttpError


# Google IoT core project settings
PROJECT_ID = "project-id"
CLOUD_REGION = "asia-east1"  # possible values "us-central1", "europe-west1", and "asia-east1"
REGISTRY_ID = "registry-id"
SERVICE_ACCOUNT_JSON = 'service_account.json'

# remove expired certs from google IoT registry
REMOVE_EXPIRED_CERTS = True

# wott api token
WOTT_API_TOKEN = '0123456789abcdef0123456789abcdef01234567'


def _error_print(e, msg):
    error = json.loads(e.content)
    print("\n{}, Code: {}, Status: {}".format(msg, error["error"]["code"], error["error"]["status"]))
    print("Message: {}\n".format(error["error"]["message"]))


def get_client(service_account_json):
    """Returns an authorized API client by discovering the IoT API and creating
    a service object using the service account credentials JSON."""
    api_scopes = ['https://www.googleapis.com/auth/cloud-platform']
    api_version = 'v1'
    discovery_api = 'https://cloudiot.googleapis.com/$discovery/rest'
    service_name = 'cloudiotcore'

    credentials = service_account.Credentials.from_service_account_file(service_account_json)
    scoped_credentials = credentials.with_scopes(api_scopes)

    discovery_url = '{}?version={}'.format(discovery_api, api_version)

    try:
        return discovery.build(
            service_name,
            api_version,
            discoveryServiceUrl=discovery_url,
            credentials=scoped_credentials
        )

    except HttpError as e:
        _error_print(e, "Error while creating Google IoT Core client")
        return None


def enroll_device(client, registry_path, device_id, certificate):
    device_template = {
        'id': device_id,
        'credentials': [{
            'publicKey': {
                'format': 'ES256_X509_PEM',
                'key': certificate,
            },
            'expirationTime': get_certificate_expiration_date(certificate).strftime('%Y-%m-%dT%H:%M:%SZ')
        }]
    }
    try:
        devices = client.projects().locations().registries().devices()
        return devices.create(parent=registry_path, body=device_template).execute()

    except HttpError as e:
        _error_print(e, "Error while enrolling device")
        return None


def patch_device(client, registry_path, device_id, credentials):

    patch = {
        'credentials': credentials
    }

    try:
        device_name = '{}/devices/{}'.format(registry_path, device_id)

        return client.projects().locations().registries().devices().patch(
            name=device_name, updateMask='credentials', body=patch).execute()

    except HttpError as e:
        _error_print(e, "Error while patching device")
        return None


def get_devices(client, registry_path):
    """Retrieve the devices."""
    dev_list = get_device_list(client, registry_path)
    if dev_list is None:
        return None
    device_list = []
    devices = client.projects().locations().registries().devices()
    for dev in dev_list:
        device_name = '{}/devices/{}'.format(registry_path, dev.get('id'))
        try:
            device = devices.get(name=device_name).execute()
        except HttpError as e:
            _error_print(e, "Error while retrieve IoT device")
            continue
        device_list.append(device)

    return device_list


def get_device_list(client, registry_path):

    try:
        devices = client.projects().locations().registries().devices(
        ).list(parent=registry_path).execute().get('devices', [])

        return devices

    except HttpError as e:
        _error_print(e, "Error while retrieving devices")
        return None


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

    cert = x509.load_pem_x509_certificate(cert_string.encode(), default_backend())

    return cert.not_valid_after.replace(tzinfo=pytz.utc)


def is_certificate_expired(cert_string):
    return datetime.datetime.now(datetime.timezone.utc) > get_certificate_expiration_date(cert_string)


def parse_wott_devices(wott_dev_list):
    devices = {}

    print("{:>50}|{:>12}".format("device name", "cert. state"))
    print("-" * 63)
    for device in wott_dev_list:
        device_id = device['device']['device_id']
        cert_resp = get_wott_device_cert(device_id)
        if cert_resp is None or not cert_resp.ok:
            print("Could not get device cert for device {} from WoTT server".format(device_id))
            cert = None
            expired = True
        else:
            cert = cert_resp.text
            expired = is_certificate_expired(cert)

        gcloud_dev_id = 'a-' + device_id if device_id[:1].isdigit() else device_id
        devices[device_id] = {
            'wott': device,
            'cert': cert,
            'gc_id': gcloud_dev_id,
            'done': False,
            'expired': expired,
            'expirationTime': get_certificate_expiration_date(cert).strftime('%Y-%m-%dT%H:%M:%SZ')
        }

        cert_state = 'Invalid' if cert is None else 'OK' if not expired else 'Expired'
        print("{:>50}|{:>12}".format(device_id, cert_state))
    print("-" * 8)
    return devices


def print_giot_devices(giot_dev_list):

    print("{:>50}|{}".format("device name", "cert. expiration"))
    print("-" * 75)
    for device in giot_dev_list:
        for idx, credential in enumerate(device.get('credentials')):
            if idx == 0:
                print("{:>50}|{}".format(device.get('id'), credential.get('expirationTime')))
            else:
                print("{:^50}|{}".format('-- ... --', credential.get('expirationTime')))

    print("-" * 8)


def main():

    def retrieve_giot_devices():
        print('\nretrieving device list from google registry...')
        dev_list = get_devices(client, registry_name)
        if dev_list is None:
            exit(1)
        print("{} devices retrieved.".format(len(dev_list)))
        print_giot_devices(dev_list)
        return dev_list

    project_id = PROJECT_ID
    cloud_region = CLOUD_REGION
    registry_id = REGISTRY_ID
    service_account_json = SERVICE_ACCOUNT_JSON

    registry_name = 'projects/{}/locations/{}/registries/{}'.format(
        project_id, cloud_region, registry_id)

    client = get_client(service_account_json)

    print('retrieving device list from wott dashboard...')
    dev_list_resp = get_wott_device_list(WOTT_API_TOKEN)
    if dev_list_resp is None or not dev_list_resp.ok:
        print("Could not get device list from WoTT server")
        exit(1)

    wott_dev_list = dev_list_resp.json()
    print("{} devices retrieved.".format(len(wott_dev_list)))
    devices = parse_wott_devices(wott_dev_list)

    gc_dev_list = retrieve_giot_devices()

    updated = 0

    for device in gc_dev_list:
        giot_dev_id = device.get('id')
        wott_dev_id = giot_dev_id[2:] if giot_dev_id[:2] == 'a-' else giot_dev_id

        if wott_dev_id in devices:
            devices[wott_dev_id]['done'] = True   # mark that this device was found and processed

            credentials = device.get('credentials')
            if credentials is None:
                credentials = []

            # if wott.cert expired and not need to remove google expired, then not need to patch
            skip = devices[wott_dev_id]['expired'] and not REMOVE_EXPIRED_CERTS

            for idx, cred in enumerate(credentials):
                if cred['publicKey']['key'] == devices[wott_dev_id]['cert']:  # cert is already here, skip that device
                    skip = True
                    break

            if skip:
                continue

            if REMOVE_EXPIRED_CERTS:
                credentials = [cred for cred in credentials if not is_certificate_expired(cred['publicKey']['key'])]

            if not devices[wott_dev_id]['expired']:
                credentials.append(
                    {
                        'publicKey': {
                            'format': 'ES256_X509_PEM',
                            'key': devices[wott_dev_id]['cert']
                        },
                        'expirationTime': devices[wott_dev_id]['expirationTime']
                    }
                )

            print("patch {} with new cert...".format(giot_dev_id))
            if patch_device(client, registry_name, giot_dev_id, credentials) is not None:
                updated += 1

    for wott_dev_id, device in devices.items():
        if not device['done'] and not device['expired']:
            # if this device was not processed in previous cycle, then it is new one. skiping expired and invalid ones.
            print("Enroll {} as {}...".format(wott_dev_id, device['gc_id']))
            if enroll_device(client, registry_name, device['gc_id'], device['cert']) is not None:
                updated += 1

    print("\n{} devices updated/enrolled.\n".format(updated))
    if updated > 0:
        retrieve_giot_devices()


if __name__ == '__main__':
    main()
