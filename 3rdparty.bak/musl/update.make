#!/usr/bin/make -f

#MUSL C library definitions
VERSION=1.1.10
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
	git clone git://nsz.repo.hu:45100/repo/libc-test
	rm -rf libc-test/.git
	rm libc-test/.gitignore

