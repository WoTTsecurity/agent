# Using WoTT with Google Core IoT

Before we get started, you need to install the `gcloud` tool. This is used to interact with Google's services. You can find installation instructions [here](https://cloud.google.com/iot/docs/how-tos/getting-started). Follow the instructions for your specific distribution.

You will also need to have at least one device with the [WoTT agent installed](https://https://github.com/WoTTsecurity/agent) if you do not already. This will provide you with your unique Device ID and token which can be added to the [WoTT dashboard](https://dash.wott.io) as per instructions. You will need the Device ID later.

Finally, you also need to have `curl` and `jq` installed (both should be available in your favorite package manager)

## Creating a registry

First we need to get the CA certificate:
```
$ curl -s https://api.wott.io/v0.2/ca | jq -r '.ca_certificate' > ca.crt
```

Next, we need to create the registry. Substitute `REGISTRY_ID` and `PROJECT_ID` with your corresponding information. You may also want to change the name of the pub/sub topic.

```
$ gcloud iot registries create REGISTRY_ID \
    --project=PROJECT_ID \
    --region=us-central1 \
    --no-enable-http-config \
    --enable-mqtt-config \
    --public-key-path=ca.crt \
    --state-pubsub-topic=wott-pubsub
```

That's it. We now have created a WoTT enabled Google CoreIoT registry. Now we need to enroll our first device.


## Enrolling devices

The first thing we need to do is to download our the certificate of the device. To do that we issue an API call to WoTT's API:


```
$ export DEVICE_ID=mydevice.d.wott.local
$ curl -s "https://api.wott.io/v0.2/device-cert/$DEVICE_ID"
```

replacing `mydevice` with the relevant certificate of your device (which can be found on the WoTT dash).
With the certificate downloaded, we can now enroll the device:

```
$ gcloud iot devices create "$DEVICE_ID" \
    --project=PROJECT_ID \
    --region=REGION \
    --registry=REGISTRY_ID \
    --public-key path=device.crt,type=es256-x509-pem
```

**Note:** Google's Device ID [must start with a letter ([a-zA-Z]))](https://cloud.google.com/iot/docs/requirements#permitted_characters_and_size_requirements), so you might need to prefix your devices, as the WoTT Device ID can start with a letter.

We now have our first device enrolled. Please do however note that the WoTT uses short-lived certificates (7 days), so you will need to upload these certificates every week.

For information on how to update/rotate the key of your device, you need to issue a PATCH command to the API. For details, see [this article](https://cloud.google.com/iot/docs/samples/device-manager-samples#patch_a_device_with_ec_credentials).


## Connecting the device

To test the connection, we will use Google's [MQTT example code](https://github.com/GoogleCloudPlatform/python-docs-samples/tree/master/iot/api-client/mqtt_example).

On your device, run the following commands

```
$ sudo apt install -y git-core python3-pip wget
$ sudo pip3 install virtualenv
$ mkdir ~/src
$ cd ~/src
$ git clone https://github.com/GoogleCloudPlatform/python-docs-samples.git
$ cd python-docs-samples/iot/api-client/mqtt_example/
$ virtualenv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ wget https://pki.google.com/roots.pem
```

We have now installed everything we need to start the agent, so let's give it a shot:


```
$ sudo -E ./venv/bin/python cloudiot_mqtt_example.py \
    --project=PROJECT_ID \
    --cloud_region=REGION \
    --registry=REGISTRY_ID \
    --device=DEVICE_ID \
    --private_key_file=/var/snap/wott-agent/current/client.key \
    --algorithm ES256 \
    --ca_certs=roots.pem \
    --message_type state \
    device_demo
```


## Verify the connection

You can now verify the connection above using either the web interface, or the `gcloud` command:

```
gcloud iot devices configs describe \
    --project=PROJECT_ID \
    --region=REGION \
    --registry=REGISTRY_ID \
    --device=DEVICE_ID

cloudUpdateTime: '2019-01-30T08:51:10.896665Z'
deviceAckTime: '2019-01-30T11:57:15.586890Z'
version: '1'
```

## Send a message

You can send a message to the device from within the Google Cloud Console. After sending the message, it should appear in the logs as such:

```
Received message 'b'Hello world'' on topic '/devices/x.d.wott.local/commands' with Qos 0
```

## Reference implementation

You may also want to take a look at our Balena [reference implementation](https://github.com/WoTTsecurity/wott-agent-balena/tree/master/google-core-iot) of the above.
