## Copyright (c) Microsoft Corporation. All rights reserved.
## Licensed under the MIT License.

all:
	$(MAKE) -C enc
	$(MAKE) -C host

clean:
	$(MAKE) -C enc clean
	$(MAKE) -C host clean

run:
	rm -rf /tmp/mmm
	./host/samplehost ./enc/sampleenc /tmp/mmm
