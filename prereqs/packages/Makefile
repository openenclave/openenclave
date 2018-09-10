# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Packages needed for building AESM and ISGX driver
PACKAGES=build-essential \
	ocaml \
	automake \
	autoconf \
	libtool \
	wget \
	python \
	libssl-dev \
	libcurl4-openssl-dev \
	protobuf-compiler \
	libprotobuf-dev \
	build-essential \
	python \
	libssl-dev \
	libcurl4-openssl-dev \
	libprotobuf-dev \
	uuid-dev \
	libxml2-dev \
	cmake \
	pkg-config \
	subversion \
	cloc \
	libexpat1 \
	libexpat1-dev \
	ccache \
	libsystemd-dev

all: .packages

.packages:
	apt-get -y install $(PACKAGES)
	touch .packages

clean:

distclean:
	rm -f .packages

install:

uninstall:
