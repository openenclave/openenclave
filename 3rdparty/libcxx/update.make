#!/usr/bin/make -f

# libcxx SVN revision
SVN_REVISON = {2017-11-07}

all: update-libcxx
	echo All done - please review changes

update-libcxx:
	rm -rf libcxx
	svn co -r $(SVN_REVISON) http://llvm.org/svn/llvm-project/libcxx/trunk libcxx
	rm -rf libcxx/.svn/
	rm libcxx/.gitignore libcxx/utils/google-benchmark/.gitignore

