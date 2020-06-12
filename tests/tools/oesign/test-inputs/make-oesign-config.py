#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

import sys
import argparse

if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description="Generates oesign config file variations from a basic valid template")
    arg_parser.add_argument('--config_file', default=None, type=str, help="Full path to output the generated oesign config file to.")
    arg_parser.add_argument('--debug', default="1", type=str, help="Value for the Debug property. Defaults to 1 (true).")
    arg_parser.add_argument('--num_heap_pages', default="1024", type=str, help="Value for the NumHeapPages property. Defaults to 1024.")
    arg_parser.add_argument('--num_stack_pages', default="1024", type=str, help="Value for the NumStackPages property. Defaults to 1024.")
    arg_parser.add_argument('--num_tcs', default="1", type=str, help="Value for the NumCS property. Defaults to 1.")
    arg_parser.add_argument('--product_id', default="1", type=str, help="Value for the ProductID property. Defaults to 1.")
    arg_parser.add_argument('--security_version', default="1", type=str, help="Value for the SecurityVersion property. Defaults to 1.")

    args = arg_parser.parse_args()

    if not args.config_file:
        arg_parser.print_help()
        sys.exit(1)

    print("Generating {} ...".format(args.config_file))
    print("Configuration used: {}".format(args))

    out_file = open(args.config_file, 'w')
    out_file.write("Debug={}\n".format(args.debug))
    out_file.write("NumHeapPages={}\n".format(args.num_heap_pages))
    out_file.write("NumStackPages={}\n".format(args.num_stack_pages))
    out_file.write("NumTCS={}\n".format(args.num_tcs))
    out_file.write("ProductID={}\n".format(args.product_id))
    out_file.write("SecurityVersion={}\n".format(args.security_version))
    out_file.close()
