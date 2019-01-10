#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

CERT_PATH=${CERT_PATH:-/opt/wott/certs}

docker build . -t wott-agent
docker run -dt \
    --net wott \
    --name wott-agent \
    -v ${CERT_PATH}:/opt/wott/certs \
    wott-agent
