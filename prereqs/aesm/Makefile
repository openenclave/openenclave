# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

.PHONY: sgx1

##==============================================================================
##
## SDK_VERSION - get the version from the se_version.h file:
##
##==============================================================================

define SDK_VERSION_SCRIPT
grep "^#define STRFILEVER[ \t]" ./linux-sgx/common/inc/internal/se_version.h 2> /dev/null | sed "s/^#define STRFILEVER[ \t][ \t]*\"\(.*\)\"/\1/g"
endef

##==============================================================================
##
## build:
##
##==============================================================================

#INSTALL_SDK=1

build: .build

.build:
	$(MAKE) linux-sgx
	$(MAKE) dynamic-application-loader-host-interface
	$(MAKE) .prebuilt
	$(MAKE) .sdk
	rm -f ./linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin
	$(MAKE) .sdk_installer
	rm -f ./linux-sgx/linux/installer/bin/sgx_linux_x64_psw_*.bin
	$(MAKE) .psw_installer
	$(MAKE) build-dynamic-application-loader-host-interface
	touch .build

linux-sgx:
	git clone https://github.com/01org/linux-sgx

dynamic-application-loader-host-interface:
	git clone https://github.com/01org/dynamic-application-loader-host-interface

.prebuilt:
	( cd linux-sgx; ./download_prebuilt.sh )
	touch .prebuilt

.sdk:
	$(MAKE) -C linux-sgx
	touch .sdk

.sdk_installer:
	$(MAKE) -C linux-sgx sdk_install_pkg
	touch .sdk_installer

.psw_installer:
	$(MAKE) -C linux-sgx psw_install_pkg
	touch .psw_installer

build-dynamic-application-loader-host-interface:
	( cd dynamic-application-loader-host-interface; cmake . )
	$(MAKE) -C dynamic-application-loader-host-interface

##==============================================================================
##
## clean:
##
##==============================================================================

clean: clean-linux-sdk clean-dynamic-application-loader-host-interface

clean-linux-sdk:
	-@ $(MAKE) -C linux-sgx clean
	rm -f .sdk .build .sdk_installer .psw_installer

clean-dynamic-application-loader-host-interface:
	-@ $(MAKE) -C dynamic-application-loader-host-interface clean

##==============================================================================
##
## distclean:
##
##==============================================================================

distclean: clean
	rm -rf linux-sgx
	rm -rf dynamic-application-loader-host-interface
	rm -f .prebuilt

##==============================================================================
##
## install:
##
##==============================================================================

ICLS_CLIENT_DEB=$(wildcard ./packages/iclsclient_*_amd64.deb)
SDK_VERSION=$(shell $(SDK_VERSION_SCRIPT) )
SDK_INSTALLER=./linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_$(SDK_VERSION).bin
PSW_INSTALLER=./linux-sgx/linux/installer/bin/sgx_linux_x64_psw_$(SDK_VERSION).bin

install:
	$(MAKE) stop
	$(MAKE) install-sdk
	$(MAKE) install-build-dynamic-application-loader-host-interface
	$(MAKE) install-psw
	$(MAKE) start

install-sdk:
ifdef INSTALL_SDK
	$(MAKE) /opt/intel/sgxsdk
endif

/opt/intel/sgxsdk:
	echo "y" >> /tmp/answers
	echo "/opt/intel" >> /tmp/answers
	$(SDK_INSTALLER) < /tmp/answers

install-psw: /opt/intel/sgxpsw

/opt/intel/sgxpsw:
	$(PSW_INSTALLER)

install-build-dynamic-application-loader-host-interface:
	$(MAKE) -C dynamic-application-loader-host-interface install
	( cd dynamic-application-loader-host-interface; systemctl enable jhi )

install-icls-client:
	dpkg -i $(ICLS_CLIENT_DEB)

##==============================================================================
##
## uninstall:
##
##==============================================================================

uninstall:
	$(MAKE) -s stop
	$(MAKE) -s uninstall-sdk
	$(MAKE) -s uninstall-psw

uninstall-sdk:
	- /opt/intel/sgxsdk/uninstall.sh 2> /dev/null > /dev/null

uninstall-psw:
	- /opt/intel/sgxpsw/uninstall.sh 2> /dev/null > /dev/null

##==============================================================================
##
## start-aesmd:
## stop-aesmd:
##
##==============================================================================

start:
	service aesmd start

stop:
	-@ service aesmd stop 2> /dev/null > /dev/null

status:
	service aesmd status

##==============================================================================
##
## sdk-version: print the SDK version:
##
##==============================================================================

sdk-version:
	@ echo $(SDK_VERSION)

