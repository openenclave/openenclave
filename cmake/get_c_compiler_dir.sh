#!/bin/bash

# obtain default compiler include holding the intrinsics
#
# Args: <CC> - The C-compiler to use
#
function exit_handler()
{
    test "$?" == 0 && return
    echo "An error occured" >&2
    exit 1
}
trap exit_handler EXIT
trap exit ERR

CC=$1

file=$(echo "#include <x86intrin.h>" | $CC -E - -M | gawk '/x86intrin\.h/{$0=gensub("-.o: ","","g"); print $1; exit}')
echo $file | grep -q 'x86intrin\.h' && test -f $file
dir=$(dirname $file)
test -d $dir
echo -n $dir
