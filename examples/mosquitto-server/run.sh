#!/bin/bash

docker run --rm \
    -p 8883:8883 \
    -v /opt/wott/certs:/opt/wott/certs:ro \
    -v $(pwd)/mosquitto.conf:/mosquitto/config/mosquitto.conf \
    eclipse-mosquitto
