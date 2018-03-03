#!/usr/bin/make -f

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all: update-libcxxrt
	echo All done - please review changes

update-libcxxrt:
	rm -rf libcxxrt
	git clone https://github.com/pathscale/libcxxrt
	rm -rf libcxxrt/.git
