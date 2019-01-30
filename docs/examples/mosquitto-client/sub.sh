#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

mosquitto_sub -v \
    --cafile /opt/wott/certs/ca.crt \
    --cert /opt/wott/certs/client.crt \
    --key /opt/wott/certs/client.key \
    -h ${MQTT_SERVER} \
    -p ${MQTT_PORT} \
    -t ${MQTT_TOPIC}
