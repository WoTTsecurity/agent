#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

docker run -d \
    --name wott-wot-tunnel \
    --net wott \
    -v /opt/wott/certs:/opt/wott/certs \
    -p 0.0.0.0:8443:8443 \
    wott-agent ghostunnel server \
    --unsafe-target \
    --listen 0.0.0.0:8443 \
    --target wott-wot:8484 \
    --keystore /opt/wott/certs/combined.pem \
    --cacert /opt/wott/certs/ca.crt \
    --allow-cn *.d.wott.local
