# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: getdist

getdist:
	$(MAKE) get-package

distclean:
	- rm -rf libsgx

build:

clean:

install:
	$(MAKE) -s uninstall
	mkdir $(INCLUDE_PATH)
	cp -f libsgx/include/* $(INCLUDE_PATH)
	mkdir $(ARCHIVE_PATH)
	cp -f libsgx/lib/static/* $(ARCHIVE_PATH)
	cp -f libsgx/lib/*.so $(LIB_PATH)

uninstall:
	- rm -rf $(INCLUDE_PATH)
	- rm -rf $(ARCHIVE_PATH)
	- rm -rf $(LIB_FILES)

##==============================================================================
##
## Helper subroutines
##
##==============================================================================

INCLUDE_PATH=/usr/local/include/libsgx
ARCHIVE_PATH=/usr/local/lib/libsgx
LIB_PATH=/usr/lib
LIB_FILES=$(addprefix $(LIB_PATH)/,$(notdir $(wildcard libsgx/lib/*)))

# Workaround until Intel-signed binary drop of libraries and enclaves built from
# https://github.com/otcshare/NextGenSGXAttestationLibs.git is available as a
# package for apt-get
get-package:
	-@ rm -f linux_ngsa_interface.tgz
	@ wget http://10.224.140.70:8888/linux_ngsa_interface.tgz
	@ tar -zxvf linux_ngsa_interface.tgz --overwrite
	-@ rm -f linux_ngsa_interface.tgz
