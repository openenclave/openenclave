#!/bin/bash


cp /output/open-enclave*.deb /tmp
pushd /tmp
apt install /tmp/open-enclave*.deb
popd

export PKG_CONFIG_PATH=/opt/openenclave/share/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig
export PATH=/opt/openenclave/bin:$PATH

cp -r /opt/openenclave/share/openenclave/samples .
pushd samples/helloworld
make
popd


