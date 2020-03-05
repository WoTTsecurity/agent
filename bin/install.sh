#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail

# Installation method for Debian derived systems
function install_on_debian_based {
  curl -s https://packagecloud.io/install/repositories/wott/agent/script.deb.sh | bash
  apt install -y wott-agent
}

function install_on_redhat_based {
  curl -s https://packagecloud.io/install/repositories/wott/agent/script.rpm.sh | bash

  # Package Cloud's script will detect Amazon Linux 2 as el/6,
  # while it should be el/7. Hotfixing this.
  PRETTY_NAME=$(grep ^PRETTY_NAME= /etc/os-release | sed 's/PRETTY_NAME=//g; s/"//g')
  if [ "$PRETTY_NAME" = "Amazon Linux 2" ]; then
    echo "Detected Amazon Linux 2"
    sed -i 's/el\/6/el\/7/g' /etc/yum.repos.d/wott_agent.repo
  fi
  yum install -y python3-wott-agent
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
    DISTRO=$(grep ^ID= /etc/os-release | sed 's/ID=//g; s/"//g')
  else
    echo "Unable to detect distribution. Exiting."
    exit 1
  fi

  # If Ubuntu/Debian is detected
  if [ "$DISTRO" = "debian" ]; then
    install_on_debian_based
  elif [ "$DISTRO" = "ubuntu" ]; then
    install_on_debian_based
  elif [ "$DISTRO" = "amzn" ]; then
    install_on_redhat_based
  elif [ "$DISTRO" = "fedora" ]; then
    echo "Detected Fedora. This is currently an unsupported distribution."
    exit 1
  elif [ "$DISTRO" = 'centos' ]; then
    echo "Detected CentOS. This is currently an unsupported distribution."
    exit 1
  else
    echo "Unknown distribution."
    exit 1
  fi
}

main
