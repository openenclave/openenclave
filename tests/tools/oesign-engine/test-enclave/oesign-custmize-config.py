#!/usr/bin/env python3
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# generate user-defined config files for oesign tests.
# usage: oesign-customize-config.py 0|1

import argparse
import os

def generate_empty_config():
    print("Generating empty config")
    cfgname = "empty.conf"
    abs_cfg = os.path.join(os.getcwd(),cfgname)
    print(abs_cfg)
    fh = open(abs_cfg, 'a+')
    fh.close()

def generate_neg_config():
    print("Generating config file w/ negative values")
    cfgname = "neg.conf"
    abs_cfg = os.path.join(os.getcwd(),cfgname)
    print(abs_cfg)
    fh = open(abs_cfg, 'a+')
    cfg_seq = [
        "NumHeapPages=-3    \n",
        "NumStackPages=1024 \n",
        "NumTCS=1           \n",
        "ProductID=1        \n",
        "SecurityVersion=1  \n"
    ]
    fh.writelines(cfg_seq)
    fh.close()

def print_help_info():
    print("Input Arguments Invalid!! Expected [0|1]!")

if __name__ == "__main__":
    print("Generating user-defined config file")
    cfg_argparser = argparse.ArgumentParser(usage='%(prog)s [0|1]',
        description='0 for empty config, 1 for neg config')

    cfg_argparser.add_argument("type", type=int,
        help="0 - empty config, 1 - config containing neg val")

    cmd_args = cfg_argparser.parse_args()

    if cmd_args.type == 0:
        generate_empty_config()
    elif cmd_args.type == 1:
        generate_neg_config()
    else:
        print_help_info()
