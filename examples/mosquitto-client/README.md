# Mosquitto MQTT client

## Pre-req's

* Docker installed
* WoTT agent running
* A WoTT enabled MQTT server running

## Usage:

### Subscribing

```
$ sudo docker build . -t wott-mqtt-client
$ export MQTT_SERVER_WOTT_ID=abc.d.wott.local
$ export MQTT_SERVER_IP=192.168.200.50
$ sudo docker run -t --rm \
    -e MQTT_SERVER=$MQTT_SERVER_WOTT_ID \
    --add-host $MQTT_SERVER_WOTT_ID:$MQTT_SERVER_IP \
    -v /opt/wott/certs:/opt/wott/certs:ro \
    wott-mqtt-client
```

### Publishing

```
$ export MQTT_SERVER_WOTT_ID=abc.d.wott.local
$ export MQTT_SERVER_IP=192.168.200.50
$ sudo docker run -t --rm \
    -e MQTT_SERVER=$MQTT_SERVER_WOTT_ID \
    -e MQTT_MESSAGE="Hellow World" \
    --add-host $MQTT_SERVER_WOTT_ID:$MQTT_SERVER_IP \
    -v /opt/wott/certs:/opt/wott/certs:ro \
    wott-mqtt-client /pub.sh
```
