# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

AZQUOTPROV=azquotprov_0.3-1_amd64.deb

all: getdist

getdist:
	$(MAKE) -s distclean
	$(MAKE) get-quote-provider

distclean:
	- rm -f $(AZQUOTPROV)

build:

clean:

install:
	$(MAKE) -s uninstall
	dpkg -i $(AZQUOTPROV)

uninstall:
	- dpkg -P azquotprov

##==============================================================================
##
## Helper subroutines
##
##==============================================================================

get-quote-provider:
ifdef USE_PKGS_IN
	cp $(USE_PKGS_IN)/$(AZQUOTPROV) .
else
	@ apt-get -y install wget
	@ wget http://10.31.100.105/$(AZQUOTPROV)
endif
