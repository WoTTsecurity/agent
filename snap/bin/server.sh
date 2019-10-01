#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail
IFS=$'\n\t'

ghostunnel server \
    --listen 0.0.0.0:${LISTEN_PORT:-8443} \
    --target 127.0.0.1:${TARGET_PORT:-8080} \
    --keystore "$SNAP_DATA/combined.pem" \
    --cacert "$SNAP_DATA/ca.crt" \
    ${CONNECTION_POLICY:---allow-all} $@
