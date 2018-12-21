FROM python:3.7-slim-stretch

ENV MQTT_SERVER localhost
ENV MQTT_PORT 8883
ENV MQTT_TOPIC wott/temperature

RUN apt-get update && \
    apt-get install -y mosquitto-clients && \
    apt-get clean

COPY sub.sh /sub.sh
COPY pub.sh /pub.sh

CMD /sub.sh
