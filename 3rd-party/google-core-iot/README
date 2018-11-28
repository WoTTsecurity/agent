# WoTT implementation of Google IoT Core's example MQTT

This is an example of how to use WoTT Agent with Google IoT Core's [MQTT Example](https://github.com/GoogleCloudPlatform/python-docs-samples/tree/master/iot/api-client/mqtt_example).

## Getting started

Spin up one or more WoTT devices. Once done, you then need to extract the following files from the first device:

 * `/opt/wott/cert/ca.crt` - This is CA certificate. This is needed to create the registry in Google Core IoT.
 * `/opt/wott/cert/client.key` - This is the device certificate that needs to be used when enrolling the device.

With the that information, you can now create your registry as per [this guide](https://cloud.google.com/iot/docs/how-tos/devices). You can skip the certificate registration since we already have finished that part, but make sure to select "ES256_X509" as the certificate type.

### Running the demo agent

To run the agent, simply run:

```
$ cd 3rd-party/google-core-iot
$ export PROJECT_ID=YourProjectId
$ export DEVICE_ID=YourDeviceID
$ export CLOUD_REGION=YourRegion
$ export REGISTRY_ID=YourRegistry
$ sudo -E ./mqtt-example.sh
```
