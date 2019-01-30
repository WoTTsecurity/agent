#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

docker run -d \
    --name wott-wot-client \
    --net wott \
    --add-host ${WOTT_SERVER_ID}:${WOTT_SERVER_IP} \
    -v /opt/wott/certs:/opt/wott/certs \
    -p 127.0.0.1:8080:8080 \
    wott-agent ghostunnel client \
    --unsafe-listen \
    --listen 0.0.0.0:8080 \
    --target ${WOTT_SERVER_ID}:${WOTT_SERVER_PORT} \
    --keystore /opt/wott/certs/combined.pem \
    --cacert /opt/wott/certs/ca.crt
