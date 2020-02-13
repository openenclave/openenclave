#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

#  Run tests of oesign.
#  We need this wrapper to return the correct return value from the tests, since
#  several invocations of oesign are supposed to fail by design.
import sys
import subprocess
import argparse

TEST_FAILED = 1
TEST_PASSED = 0


if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description='test cases for oesign engine support' )
    arg_parser.add_argument("--oesign-binary", default=None, type=str, help="oe-sign binary" )
    arg_parser.add_argument("--enclave-binary", default=None, type=str, help="enclave binary to be signed" )
    arg_parser.add_argument("--config-file", default=None, type=str, help="signing config" )
    arg_parser.add_argument("--engine-id", default=None, type=str, help="openssl engine name" )
    arg_parser.add_argument("--key-id", default=None, type=str, help="openssl engine key identifier" )
    arg_parser.add_argument("--engine-load-path", default=None, type=str, help="openssl engine load path" )
    arg_parser.add_argument("--expect-fail", help="test succeeds on utility error", action="store_true" )

    args = arg_parser.parse_args()
    print(args)

    if not args.config_file or \
       not args.enclave_binary or \
       not args.engine_id or \
       not args.engine_load_path or \
       not args.key_id or \
       not args.oesign_binary:

        arg_parser.print_help()
        sys.exit ( 1 )

    test_rslt = TEST_PASSED
    cmd = args.oesign_binary+' sign -e '+args.enclave_binary+' -c '+args.config_file+' -n '+args.engine_id+' -p '+args.engine_load_path+' -i '+args.key_id

    retval = subprocess.call(cmd, shell=True)
    # should return a failed retval
    if args.expect_fail:
        if retval == 0:
            test_rslt  = TEST_FAILED
            print("oesign-test FAIL:\nretval %x\n" % (retval))
    else:
        if retval != 0:
            test_rslt  = TEST_FAILED
            print("oesign-test FAIL:\nretval %x\n" % (retval))

    sys.exit ( test_rslt )


