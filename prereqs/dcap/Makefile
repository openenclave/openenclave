# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

PACKAGE_NAMES=\
	libsgx-enclave-common\
	libsgx-enclave-common-dev\
	libsgx-dcap-ql\
	libsgx-dcap-ql-dev\

PACKAGES=\
	libsgx-enclave-common_2.3.100.46354-1_amd64.deb\
	libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb\
	libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb\
	libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb\

PACKAGE_URLS=\
	https://download.01.org/intel-sgx/dcap-1.0/SGX_installers/ubuntu16.04/libsgx-enclave-common_2.3.100.46354-1_amd64.deb\
	https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/libs/libsgx-enclave-common-dev/libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb\
	https://download.01.org/intel-sgx/dcap-1.0/DCAP_installers/ubuntu16.04/libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb\
	https://download.01.org/intel-sgx/dcap-1.0/DCAP_installers/ubuntu16.04/libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb\

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
reverse-list = $(if $(wordlist 2,2,$(1)),\
	$(call reverse-list,$(wordlist 2,$(words $(1)),$(1))) $(firstword $(1)),$(1))

PACKAGES_INSTALLED=\
	$(foreach PKG,$(PACKAGE_NAMES),\
		$(if $(call is-pkg-installed,$(PKG)),\
			"Verified: $(PKG) package installed",\
			"*** Failed to install $(PKG) package"))

# Workaround until these packages are available via apt-get directly
get-package:
	apt-get -y install wget dpkg-dev libprotobuf9v5
ifdef USE_PKGS_IN
	@ for PKG in $(PACKAGES); do \
		cp $(USE_PKGS_IN)/$$PKG .; \
	done
else
	@ for PKG_URL in $(PACKAGE_URLS); do \
		wget $$PKG_URL; \
	done
endif

check-installed:
	@ for PKG in $(PACKAGES_INSTALLED); do \
		echo $$PKG; \
	done

ifneq ($(findstring Failed,$(PACKAGES_INSTALLED)),)
	@ exit 1
endif
