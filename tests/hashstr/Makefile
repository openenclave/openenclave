# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

include ../../mak/defs.mak

all:
	gcc -Wall -O3 -o hashstr main.c strings.c

tests:
	/usr/bin/time ./hashstr

clean:
	rm hashstr
