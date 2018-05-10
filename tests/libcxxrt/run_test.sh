# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

test_command=$1
test_command1=$2
expected_output=$3
test_log=$4
$test_command $test_command1 > $test_log 2>&1
diff $test_log $expected_output

