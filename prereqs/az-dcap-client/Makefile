# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

AZ_DCAP_PKG=az-dcap-client_1.0_amd64.deb

all: getdist

getdist:
	$(MAKE) -s distclean
	$(MAKE) get-quote-provider

distclean:
	- rm -f $(AZ_DCAP_PKG)

build:

clean:

install:
	$(MAKE) -s uninstall
	dpkg -i $(AZ_DCAP_PKG)

uninstall:
	- dpkg -P az-dcap-client

##==============================================================================
##
## Helper subroutines
##
##==============================================================================

get-quote-provider:
ifdef USE_PKGS_IN
	cp $(USE_PKGS_IN)/$(AZ_DCAP_PKG) .
else
	@ apt-get -y install wget
	@ wget https://packages.microsoft.com/repos/microsoft-ubuntu-xenial-prod/pool/main/a/az-dcap-client/$(AZ_DCAP_PKG)
endif
