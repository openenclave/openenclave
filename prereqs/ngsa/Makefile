# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

LIBSGX_COMMON=libsgx-enclave-common
LIBSGX_QL=libsgx-ngsa-ql
PACKAGE_VER=2.1.100.0-1.0_amd64

LIBSGX_COMMON_PKG=$(call pkg-name,$(LIBSGX_COMMON),$(PACKAGE_VER))
LIBSGX_QL_PKG=$(call pkg-name,$(LIBSGX_QL),$(PACKAGE_VER))

LIBSGX_COMMON_INSTALLED = $(call is-pkg-installed,$(LIBSGX_COMMON))
LIBSGX_QL_INSTALLED = $(call is-pkg-installed,$(LIBSGX_QL))

all: getdist

getdist:
	$(MAKE) -s distclean
	$(MAKE) get-package

distclean:
	- rm -f $(LIBSGX_COMMON_PKG)
	- rm -f $(LIBSGX_QL_PKG)

build:

clean:

install:
	dpkg -i $(LIBSGX_COMMON_PKG)
	dpkg -i $(LIBSGX_QL_PKG)
	$(MAKE) check-installed

uninstall:
	- dpkg -P $(LIBSGX_QL)
	- dpkg -P $(LIBSGX_COMMON)

##==============================================================================
##
## Helper subroutines
##
##==============================================================================

is-pkg-installed = $(shell dpkg-query -s $(1) | grep "Status: .* installed")
pkg-name = $(1)_$(2).deb

# Workaround until Intel-signed binary drops of libraries and enclaves from
# https://github.com/otcshare/NextGenSGXAttestationLibs.git are available as
# packages for apt-get
get-package:
	apt-get -y install wget
	@ wget http://10.224.140.70:8888/libsgx-enclave-common_2.1.100.0-1.0_amd64.deb
	@ wget http://10.224.140.70:8888/libsgx-ngsa-ql_2.1.100.0-1.0_amd64.deb

check-installed:
ifeq ($(LIBSGX_COMMON_INSTALLED)),)
	@ echo "*** Failed to install $(LIBSGX_COMMON) package"
	@ exit 1
else
	@ echo "Verified: $(LIBSGX_COMMON) package installed"
endif
ifeq ($(LIBSGX_QL_INSTALLED),)
	@ echo "*** Failed to install $(LIBSGX_QL) package"
	@ exit 1
else
	@ echo "Verified: $(LIBSGX_QL) package installed"
endif
