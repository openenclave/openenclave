#!/usr/bin/make -f

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# libcxx SVN revision
SVN_REVISON = RELEASE_700

all: update-libcxx
	echo All done - please review changes

update-libcxx:
	rm -rf libcxx
	svn co  http://llvm.org/svn/llvm-project/libcxx/tags/$(SVN_REVISON)/final/
	mv final libcxx
	rm -rf libcxx/.svn/
	rm libcxx/.gitignore libcxx/utils/google-benchmark/.gitignore

