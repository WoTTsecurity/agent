# docker run --net=host --cap-add=NET_ADMIN --cap-add=SYS_ADMIN  -v /sys/fs/cgroup:/sys/fs/cgroup:ro --security-opt seccomp:unconfined -v ~/Documents/GreatFruit/WoTT:/usr/src/app -Pit mydebian
FROM debian
WORKDIR /usr/src/app

RUN apt-get update && \
    apt-get install -y build-essential libssl-dev libffi-dev libltdl-dev openssh-server git net-tools \
        iptables inetutils-ping wget curl pkg-config libsystemd-dev nmap python3-iptables python3-setuptools python3-pip && \
    service ssh start && \
    mkdir /root/.ssh

COPY id_rsa.pub /root/.ssh/
COPY id_rsa.pub /root/.ssh/authorized_keys
COPY id_rsa /root/.ssh/

RUN chmod 600 /root/.ssh/*

COPY requirements.txt ./
COPY requirements-dev.txt ./
RUN pip3 install -r requirements-dev.txt
CMD bash
