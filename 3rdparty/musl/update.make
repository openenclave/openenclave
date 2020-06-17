#!/usr/bin/make -f

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# MUSL C library definitions
VERSION=1.1.21
BASE=musl-$(VERSION)
PKG=$(BASE).tar.gz

all: update-musl update-libc-test
	echo All done - please review changes

update-musl:
	rm -rf musl
	wget http://www.musl-libc.org/releases/$(PKG)
	tar zxf $(PKG)
	mv $(BASE) musl
	rm -rf $(PKG)
	rm musl/.gitignore

update-libc-test:
	rm -rf libc-test
	git clone git://repo.or.cz/libc-test
	git -C libc-test checkout a51df71b050f3f9dfdc0a7d90978b57277b582ec
	rm -rf libc-test/.git
	rm libc-test/.gitignore

