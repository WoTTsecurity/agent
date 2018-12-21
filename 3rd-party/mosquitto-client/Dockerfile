FROM python:3.7-slim-stretch

ENV MQTT_SERVER localhost
ENV MQTT_PORT 8883
ENV MQTT_TOPIC wott/temperature

RUN apt-get update && \
    apt-get install -y mosquitto-clients && \
    apt-get clean

CMD mosquitto_sub \
    --cafile /opt/wott/certs/ca.crt \
    --cert /opt/wott/certs/client.crt \
    --key /opt/wott/certs/client.key \
    -h ${MQTT_SERVER} \
    -p ${MQTT_PORT} \
    -t ${MQTT_TOPIC}
