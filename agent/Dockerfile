## Dependency build environment
FROM golang:1.11.2-stretch as build

WORKDIR /go/src/

RUN apt-get update && \
    apt-get install -y --no-install-recommends libltdl-dev && \
    apt-get clean

RUN git clone https://github.com/square/ghostunnel.git $GOPATH/src/github.com/square/ghostunnel && \
    cd  $GOPATH/src/github.com/square/ghostunnel && \
    git checkout -b v1.3.0 && \
    make

RUN git clone https://github.com/cloudflare/cfssl.git $GOPATH/src/github.com/cloudflare/cfssl && \
    cd $GOPATH/src/github.com/cloudflare/cfssl && \
    git checkout -b 5d63dbd981b5c408effbb58c442d54761ff94fbd && \
    make

## Runtime container
FROM python:3.7-slim-stretch
WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev libltdl-dev && \
    apt-get clean

COPY --from=build /go/src/github.com/square/ghostunnel/ghostunnel /usr/local/bin/
COPY --from=build /go/src/github.com/cloudflare/cfssl/bin/* /usr/local/bin/

RUN mkdir -p /opt/wott/certs

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .

CMD ./agent.py
