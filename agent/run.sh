#!/bin/bash

docker build . -t wott-agent
docker run \
    --rm \
    --name wott-agent \
    -v /opt/wott/cert:/opt/wott/cert \
    wott-agent
