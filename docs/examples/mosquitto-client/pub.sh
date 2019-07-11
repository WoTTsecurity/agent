#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

while true; do
	TEMPERATURE=$(shuf -i1-50 -n1)
	echo "Sending temperature $TEMPERATURE"
	mosquitto_pub \
		--cafile /opt/wott/certs/ca.crt \
		--cert /opt/wott/certs/client.crt \
		--key /opt/wott/certs/client.key \
		-h ${MQTT_SERVER} \
		-p ${MQTT_PORT} \
		-t ${MQTT_TOPIC} \
		-m "${TEMPERATURE}"
	sleep 2
done
