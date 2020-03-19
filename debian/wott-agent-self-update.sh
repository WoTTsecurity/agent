#!/bin/bash
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-

set -euo pipefail

DISTRO=$(grep ^ID= /etc/os-release | sed 's/ID=//g; s/"//g')
case $DISTRO in
  debian | ubuntu)
    echo "deb-based"
    apt-get update
    apt-get install -ys wott-agent
    ;;
  amzn | fedora | centos)
    echo "rpm-based"
    yum update -y python3-wott-agent
    ;;
  *)
    echo "unknown"
    ;;
esac