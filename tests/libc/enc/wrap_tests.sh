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

if [ "$#" != "2" ]; then
    echo "Usage: $0 INPUT_FILE OUTPUT_DIRECTORY"
    exit 1
fi

input_file=$1
output_directory=$2

if [ ! -f "${input_file}" ]; then
    echo "$0: not found: ${input_file}"
    exit 1
fi

if [ ! -d "${output_directory}" ]; then
    echo "$0: not found: ${output_directory}"
    exit 1
fi

# Form the list of files while stripping the "${ROOT}/" prefix.
files=$(grep "^[ \t]*\${ROOT}/" "${input_file}" | sed "s~[ \t]*\${ROOT}/~~g")

##==============================================================================
##
## Remove all previously generated files.
##
##==============================================================================

tests_c=${output_directory}/tests.c

rm -f "${tests_c}"
rm -f "${output_directory}/test_*.c"

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
    name=$(get_test_name "${i}")
    dirname=$(dirname "${i}")
    basename=$(basename "${i}")

    # Create the directory for this source.
    mkdir -p "${output_directory}/${dirname}"


    # Form the full path of the source file.
    source_file=${output_directory}/${dirname}/${basename}

    # Create the wrapper source file.
cat > "${source_file}" <<END
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define main ${name}
#include "../../../${i}"
END
    echo "Created ${source_file}"
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
