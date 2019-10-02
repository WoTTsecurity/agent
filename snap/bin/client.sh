#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

ghostunnel client \
    --listen 127.0.0.1:${LISTEN_PORT:-8080} \
    --target ${TARGET_IP}:${TARGET_PORT:-8443} \
    --override-server-name=${TARGET_WOTT_ID} \
    --keystore "$SNAP_DATA/combined.pem" \
    --cacert "$SNAP_DATA/ca.crt"
