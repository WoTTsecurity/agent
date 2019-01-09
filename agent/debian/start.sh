#!/bin/bash -e
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- sh-basic-offset: 4 -*-


mkdir -p /tmp/python-deb-pkg/debian/dist

if [ -e ./debian/dist/*.deb ]; then \
    rm -f ./debian/dist/*.deb ./debian/dist/*.changes; \
fi;

dpkg-buildpackage -B -us -uc --changes-option=-udebian/dist/

# Copy out the files
cp -v /tmp/python-deb-pkg/debian/dist/*.deb /dist/
cp -v ../*.changes /dist/
