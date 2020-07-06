#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import sys
import argparse

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description="Generates oesign key file for test")
    arg_parser.add_argument('--input', default=None, type=str, required=True, help="Full path to the input key file(correct private key)")
    arg_parser.add_argument('--outfile', default=None, type=str, required=True, help="Full path to the output key file(incorrect key)")

    args = arg_parser.parse_args()
    print("input file: " + args.input)
    print("out file: " + args.outfile)

    in_file = open(args.input, 'r')
    out_file = open(args.outfile, 'w+')

    out_file_name = args.outfile
    s = format(in_file.read())

    if out_file_name.find("wrong_format") >= 0:
        print("Generate wrong format key")
        out_file.write(s + "Proc-Type: 4, ENCRYPTED")
    elif out_file_name.find("end_wrong") >= 0:
        print("Generate key with wrong end")
        end_str = "-----END RSA PRIVATE KEY-----"
        incorrect_end_str = "-----WRONG RSA PRIVATE KEY-----"
        if s.find(end_str) > 0:
            s = s.replace(end_str, incorrect_end_str)
            out_file.write(s)
        else:
            print("no end str found in file:" + format(args.input))
    else:
        print("please check the out file name")
    in_file.close()
    out_file.close()
