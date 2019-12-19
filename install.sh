#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
    echo "Please run as root or using sudo"
    exit 1
fi

mkdir -p /opt/wott

if [ ! -f /etc/wott/config.ini ]; then
    echo -e "[DEFAULT]\\nenroll_token = $CLAIM_TOKEN" > /opt/wott/config.ini
fi

# If Ubuntu/Debian is detected
if [ -f /etc/lsb-release ]; then
    # Install repository from Package Cloud
    curl -s https://packagecloud.io/install/repositories/wott/agent/script.deb.sh | bash
    apt install -y wott-agent
fi

# If RHEL/CentOS/Amazon Linux is detected (for when we add support)
#if [ -f /etc/redhat-release ]; then
#    yum update
#fi
