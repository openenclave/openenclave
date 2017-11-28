#!/usr/bin/make -f

all: update-libcxxrt
	echo All done - please review changes

update-libcxxrt:
	rm -rf libcxxrt
	git clone https://github.com/pathscale/libcxxrt
	rm -rf libcxxrt/.git
