#!/usr/bin/make -f

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#libunwind Version
VERSION=1.3
BRANCH=v$(VERSION)-stable

all: update-libunwind
	echo All done - please review changes

update-libunwind:
	rm -rf libunwind
	git clone https://github.com/libunwind/libunwind/ -b $(BRANCH)
	rm -rf libunwind/aux
	rm -rf libunwind/.git
