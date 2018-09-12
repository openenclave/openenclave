# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

PACKAGE_VER=1.0.101.45575-1.0_amd64

PACKAGE_NAMES=\
	libsgx-enclave-common\
	libsgx-enclave-common-dev\
	libsgx-ngsa-ql\
	libsgx-ngsa-ql-dev\

PACKAGES=$(foreach NAME,$(PACKAGE_NAMES),$(call pkg-name,$(NAME),$(PACKAGE_VER)))

UNINSTALL_NAMES=$(call reverse-list,$(PACKAGE_NAMES))

all: getdist

getdist:
	$(MAKE) -s distclean
	$(MAKE) get-package

distclean:
	-@ for PKG in $(PACKAGES); do \
		rm -f $$PKG; \
	done

build:

clean:

install:
	@ for PKG in $(PACKAGES); do \
		dpkg -i $$PKG; \
	done
	$(MAKE) check-installed

uninstall:
	@ for PKG in $(UNINSTALL_NAMES); do \
		dpkg -P $$PKG 2>/dev/null; \
	done

##==============================================================================
##
## Helper subroutines
##
##==============================================================================

is-pkg-installed = $(shell dpkg-query -s $(1) 2>/dev/null | grep "Status: .* installed")
pkg-name = $(1)_$(2).deb
reverse-list = $(if $(wordlist 2,2,$(1)),\
	$(call reverse-list,$(wordlist 2,$(words $(1)),$(1))) $(firstword $(1)),$(1))

PACKAGES_INSTALLED=\
	$(foreach PKG,$(PACKAGE_NAMES),\
		$(if $(call is-pkg-installed,$(PKG)),\
			"Verified: $(PKG) package installed",\
			"*** Failed to install $(PKG) package"))

# Workaround until Intel-signed binary drops of libraries and enclaves from
# https://github.com/otcshare/NextGenSGXAttestationLibs.git are available as
# packages for apt-get
get-package:
	apt-get -y install wget dpkg-dev
ifdef USE_PKGS_IN
	@ for PKG in $(PACKAGES); do \
		cp $(USE_PKGS_IN)/$$PKG .; \
	done
else
	@ for PKG in $(PACKAGES); do \
		wget http://10.31.100.105/$$PKG; \
	done
endif

check-installed:
	@ for PKG in $(PACKAGES_INSTALLED); do \
		echo $$PKG; \
	done

ifneq ($(findstring Failed,$(PACKAGES_INSTALLED)),)
	@ exit 1
endif
