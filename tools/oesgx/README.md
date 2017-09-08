oesgx
=====

This directory contains the oesgx tool, which determines the level of 
SGX support for the given CPU. It printfs one of these:

    0 -- no support
    1 -- SGX-1
    2 -- SGX-2

For example:

    $ ./oesgx
    1

