#!/bin/bash

# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## wrap_tests.sh INPUT_FILE OUTPUT_DIRECTORY
##
##     This script reads the test sources from INPUT_FILE and creates wrappers 
##     for each of them in the OUTPUT_DIRECTORY.
##
##==============================================================================

##==============================================================================
##
## Check command line arguments.
##
##==============================================================================

if [ "$#" -lt "3" ]; then
    echo "Usage: $0 IN_DIR OUT_DIR SOURCES..."
    exit 1
fi

in_dir=$1
out_dir=$2
input_files=$3

if [ ! -d "${in_dir}" ]; then
    echo "$0: not found: ${in_dir}"
    exit 1
fi

if [ ! -d "${out_dir}" ]; then
    echo "$0: not found: ${out_dir}"
    exit 1
fi

files=$(/bin/echo "${input_files}" | sed 's/;/ /g')

for i in ${files}
do
    if [ ! -f "${in_dir}/${i}" ]; then
        echo "$0: not found: ${in_dir}/${i}"
        exit 1
    fi
done

##==============================================================================
##
## Remove all previously generated files.
##
##==============================================================================

tests_c=${out_dir}/tests.c

rm -f "${tests_c}"
rm -f "${out_dir}/test_*.c"

##==============================================================================
##
## get_test_name()
##
##     Convert a path to a test name that is suitable as a C identifier.
##
##==============================================================================

get_test_name()
{
    name=$(echo "$1" | sed "s~[\.\/\-]~_~g" | sed "s~______3rdparty_musl_libc_test_src_~test_~g")
    echo "_${name}"
}

##==============================================================================
##
## Generate the individual test source files.
##
##==============================================================================

for i in ${files}
do
    in_file=${in_dir}/${i}
    test_name=$(get_test_name "${i}")
    dirname=$(dirname "${i}")
    basename=$(basename "${i}")

    # Create the directory for this source.
    mkdir -p "${out_dir}/${dirname}"

    # Form the full path of the source file.
    out_file=${out_dir}/${dirname}/${basename}

    # Create the wrapper source file.
cat > "${out_file}" <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define main ${test_name}
#include "${in_file}"
END
    echo "Created ${out_file}"
done

##==============================================================================
##
## Generate tests.c
##
##==============================================================================


cat >> "${tests_c}" <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

extern int run_test(
    const char* name,
    int (*main)(int argc, const char* argv[]));

int run_tests(void)
{
    int ret = 0;
END

for i in ${files}
do
    name=$(get_test_name "${i}")

cat >> "${tests_c}" <<END
    extern int ${name}(int argc, const char* argv[]);
END

cat >> "${tests_c}" <<END
    ret += run_test("${name}", ${name});
END

done

cat >> "${tests_c}" <<END
    return ret;
}
END

echo "Created ${tests_c}"
