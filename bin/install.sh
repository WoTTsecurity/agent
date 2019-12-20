#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail

# Installation method for Debian derived systems
function install_on_debian_based {
    curl -s https://packagecloud.io/install/repositories/wott/agent/script.deb.sh | bash
    apt install -y wott-agent
}

# Wrap everything in a function to ensure
# that we don't get a partial run.
function main {
    if [[ $(id -u) -ne 0 ]]; then
        echo "Please run as root or using sudo"
        exit 1
    fi

    mkdir -p /opt/wott

    if [ ! -f /opt/wott/config.ini ]; then
        echo -e "[DEFAULT]\\nenroll_token = $CLAIM_TOKEN" > /opt/wott/config.ini
    fi

    # This should for all recent versions of Debian and Ubuntu
    # as well as CentOS 7 or later.
    if [ -f /etc/os-release ]; then
        DISTRO=$(grep ^ID= /etc/os-release | sed 's/ID=//g')
    else
        echo "Unable to detect distribution. Exiting."
        exit 1
    fi

    # If Ubuntu/Debian is detected
    if [ "$DISTRO" = "debian" ]; then
        install_on_debian_based
    elif [ "$DISTRO" = "ubuntu" ]; then
        install_on_debian_based
    elif [ "$DISTRO" = "fedora" ]; then
        echo "Detected Fedora. This is currently an unsupported distribution."
        exit 1
    elif [ "$DISTRO" = '"centos"' ]; then
        echo "Detected CentOS. This is currently an unsupported distribution."
        exit 1
    fi
}

main
