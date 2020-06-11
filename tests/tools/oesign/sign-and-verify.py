#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import sys
import subprocess
import argparse

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description="Invokes the oesign sign command and attempts to load the signed enclave")
    arg_parser.add_argument('--oesign-path', default=None, type=str, help="Path to the oesign tool")
    arg_parser.add_argument('--oesign-args', default=None, type=str, help="Additional arguments to be passed to oesign")
    arg_parser.add_argument('--enclave-path', default=None, type=str, help="Path to the enclave binary to be signed")
    arg_parser.add_argument('--host-path', default=None, type=str, help="Path to the enclave host app used to launch the enclave")

    args = arg_parser.parse_args()
    print(args)

    if not args.enclave_path or \
       not args.host_path or \
       not args.oesign_args or \
       not args.oesign_path:

        arg_parser.print_help()
        sys.exit(1)

    sign_cmd = "{} sign --enclave {} {}".format(args.oesign_path, args.enclave_path, args.oesign_args)
    launch_cmd = "{} {}.signed".format(args.host_path, args.enclave_path)

    retval = subprocess.call(sign_cmd, shell=True)
    if retval != 0:
        print("FAIL: (error:{}) {}".format(retval, sign_cmd))
        sys.exit(retval)
    else:
        print("PASS: Sign succeeded with ({})".format(sign_cmd))

    retval = subprocess.call(launch_cmd, shell=True)
    if retval != 0:
        print("FAIL: (error:{}) {}".format(retval, launch_cmd))
        sys.exit(retval)
    else:
        print("PASS: Launch of signed enclave succeeded ({})".format(launch_cmd))

    sys.exit(retval)
