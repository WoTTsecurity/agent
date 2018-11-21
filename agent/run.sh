#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

docker build . -t wott-agent
docker run \
    --rm -ti \
    --net wott \
    --name wott-agent \
    -v /opt/wott/certs:/opt/wott/certs \
    -e CFSSL_SERVER=${CFSSL_SERVER:-localhost} \
    -e CFSSL_PORT=${CFSSL_PORT:-8888} \
    wott-agent
