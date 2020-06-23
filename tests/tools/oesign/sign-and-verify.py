#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import argparse
import subprocess
import sys

def call_subprocess(cmd, success_message):
    retval = subprocess.call(cmd, shell=True)
    if retval != 0:
        print("FAIL: (error:{}) {}".format(retval, cmd))
        sys.exit(retval)
    else:
        print("PASS: {} ({})".format(success_message, cmd))

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description="Invokes the oesign sign command and attempts to load the signed enclave")
    arg_parser.add_argument('--oesign-path', default=None, type=str, help="Path to the oesign tool")
    arg_parser.add_argument('--oesign-args', default=None, type=str, help="Additional arguments to be passed to oesign")
    arg_parser.add_argument('--enclave-path', default=None, type=str, help="Path to the enclave binary to be signed")
    arg_parser.add_argument('--host-path', default=None, type=str, help="Path to the enclave host app used to launch the enclave")
    arg_parser.add_argument('--digest-args', default=None, type=str, help="Optional. If provided, sign-and-verify.py will call the oesign digest command with the provided arguments before all other operations.")
    arg_parser.add_argument('--pkeyutl-args', default=None, type=str, help="Optional. If provided, sign-and-verify.py will call openssl pkeyutl after digest creation and before oesign. This should specify the input digest, output signature file name and key to use to sign a digest.")

    args = arg_parser.parse_args()
    print("Arguments parsed: {}".format(args))

    if not args.enclave_path or \
       not args.host_path or \
       not args.oesign_args or \
       not args.oesign_path:

        arg_parser.print_help()
        sys.exit(1)

    if args.digest_args:
        digest_cmd = "{} digest --enclave {} {}".format(args.oesign_path, args.enclave_path, args.digest_args)
        call_subprocess(digest_cmd, "Digest succeeded")

    if args.pkeyutl_args:
        sign_digest_cmd = "openssl pkeyutl -sign -pkeyopt digest:sha256 {}".format(args.pkeyutl_args)
        call_subprocess(sign_digest_cmd, "Signing of digest succeeded")

    sign_cmd = "{} sign --enclave {} {}".format(args.oesign_path, args.enclave_path, args.oesign_args)
    call_subprocess(sign_cmd, "Sign succeeded")

    launch_cmd = "{} {}.signed".format(args.host_path, args.enclave_path)
    call_subprocess(launch_cmd, "Launch of signed enclave succeeded")

    sys.exit(0)
