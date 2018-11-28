#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

docker build . -t wott-google-mqtt
docker run -ti \
    -e DEVICE_ID=${DEVICE_ID-$(hostname)} \
    -e REGISTRY_ID=${REGISTRY_ID} \
    -e CLOUD_REGION=${CLOUD_REGION:-europe-west1} \
    -e PROJECT_ID=${PROJECT_ID} \
    wott-google-mqtt
