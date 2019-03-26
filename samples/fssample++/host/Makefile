# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

all:
	/opt/openenclave/bin/oeedger8r --untrusted ../sample.edl
	oe-host-g++ -o samplehost host.cpp sample_u.c

clean:
	rm -f samplehost host.o sample*
