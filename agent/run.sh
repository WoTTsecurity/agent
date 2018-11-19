#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

docker build . -t wott-agent
docker run \
    --rm -ti \
    --name wott-agent \
    -v /opt/wott/cert:/opt/wott/cert \
    wott-agent
