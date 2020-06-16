#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import argparse
import subprocess
import sys

def call_subprocess(cmd, success_message):
    retval = subprocess.call(cmd)
    if retval != 0:
        print("FAIL: (error:{}) {}".format(retval, cmd))
        sys.exit(retval)
    else:
        print("PASS: {} ({})".format(success_message, cmd))

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description="Invokes the oesign sign command and attempts to load the signed enclave")
    arg_parser.add_argument('--oesign-path', default=None, type=str, required=True, help="Path to the oesign tool")
    arg_parser.add_argument('--oesign-args', default=None, type=str, required=True, help="Additional arguments to be passed to oesign")
    arg_parser.add_argument('--enclave-path', default=None, type=str, required=True, help="Path to the enclave binary to be signed")
    arg_parser.add_argument('--host-path', default=None, type=str, required=True, help="Path to the enclave host app used to launch the enclave")
    arg_parser.add_argument('--digest-args', default=None, type=str, help="Optional. If provided, sign-and-verify.py will call the oesign digest command with the provided arguments before all other operations.")
    arg_parser.add_argument('--pkeyutl-args', default=None, type=str, help="Optional. If provided, sign-and-verify.py will call openssl pkeyutl after digest creation and before oesign. This should specify the input digest, output signature file name and key to use to sign a digest.")

    args = arg_parser.parse_args()
    print("Arguments parsed: {}".format(args))

    # Note that the arguments that take multiple values use a string format `[a,b,...]` that are parsed out
    # into lists separately with strip and split operations. While argparse supports taking variable nargs, it doesn't like
    # taking argument values that look like argument names (begin with '-' or '--') which is what we pass into this function.
    # This script expects the argument list strings in brackets to avoid this interaction with argparse, and extends the
    # basic argument list with the parsed list of arguments. While it's preferable to use the * operator for the list
    # concatenation, it's only available on Python 3.6+ and that's not a currently stated OE SDK requirement on Ubuntu.

    if args.digest_args:
        digest_cmd = [args.oesign_path, "digest", "--enclave-image", args.enclave_path]
        digest_cmd.extend(args.digest_args.strip('[]').split(','))
        print("digest_cmd = {}".format(digest_cmd))
        call_subprocess(digest_cmd, "Digest succeeded")

    if args.pkeyutl_args:
        sign_digest_cmd = ["openssl", "pkeyutl", "-sign", "-pkeyopt", "digest:sha256"]
        sign_digest_cmd.extend(args.pkeyutl_args.strip('[]').split(','))
        call_subprocess(sign_digest_cmd, "Signing of digest succeeded")

    sign_cmd = [args.oesign_path, "sign", "--enclave-image", args.enclave_path]
    sign_cmd.extend(args.oesign_args.strip('[]').split(','))
    call_subprocess(sign_cmd, "Sign succeeded")

    launch_cmd = [args.host_path, "{}.signed".format(args.enclave_path)]
    call_subprocess(launch_cmd, "Launch of signed enclave succeeded")

    sys.exit(0)
