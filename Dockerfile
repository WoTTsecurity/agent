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

## Runtime container
FROM python:3.7-slim-stretch
WORKDIR /usr/src/app
ENV PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev libltdl-dev \
                                               curl pkg-config libsystemd-dev iptables nmap \
 && apt-get clean

COPY --from=build /go/src/github.com/square/ghostunnel/ghostunnel /usr/local/bin/

RUN mkdir -p /opt/wott/certs

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./
RUN python setup.py install

CMD wott-agent
