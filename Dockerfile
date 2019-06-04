FROM debian:stretch
WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y build-essential libssl-dev libffi-dev libltdl-dev git net-tools \
        iptables inetutils-ping wget curl pkg-config libsystemd-dev nmap \
        python3-iptables python3-setuptools python3-pip

COPY requirements.txt ./
COPY requirements-dev.txt ./
RUN pip3 install -r requirements-dev.txt
CMD bash
