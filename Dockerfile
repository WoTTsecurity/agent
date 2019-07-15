FROM debian:buster
WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y build-essential libssl-dev libffi-dev libltdl-dev git net-tools iptables inetutils-ping wget \
        curl pkg-config libsystemd-dev nmap python3-setuptools python3-all python3-pkg-resources python3-iptables \
        python3-psutil python3-certifi python3-cffi python3-chardet python3-cryptography python3-idna \
        python3-netifaces python3-openssl python3-tz python3-requests python3-sh python3-systemd python3-venv \
        python3-pip

COPY requirements-dev.txt ./
RUN pip3 install -r requirements-dev.txt
CMD bash
