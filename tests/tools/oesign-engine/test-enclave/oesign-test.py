#!/usr/bin/env python3
#  Run tests of oesign.
#  We need this wrapper to return the correct return value from the tests, since 
#  several invocations of oesign are supposed to fail by design.
import sys
import subprocess
import argparse

def oesign_works(oesign_binary:str, enclave:str, config_file:str, engine_id: str, keyid:str, loadpath: str  ) -> int: 
    cmd = oesign_binary+' sign -e '+enclave+' -c '+config_file+' -n '+engine_id+' -p '+loadpath+' -i '+keyid

    return subprocess.run(cmd, shell=True)

def oesign_detects_failed_engine_path(oe_sign_binary:str, enclave:str, config_file:str, engine_id: str, keyid:str, loadpath: str  ) -> int: 
    # ignore loadpath
    loadpath = '/tmp/not_there'
    cmd = oesign_binary+' sign -e '+enclave+' -c '+config_file+' -n '+engine_id+' -p '+loadpath+' -i '+keyid

    retval = subprocess.run(cmd, shell=True)
    # should return a failed retval
    return retval != 0

def oesign_detects_failed_engine_id(oe_sign_binary:str, enclave:str, config_file:str, engine_id: str, keyid:str, loadpath: str  ) -> int: 
    # ignore engine_id
    engine_id = 'bogus_engine'
    cmd = oesign_binary+' sign -e '+enclave+' -c '+config_file+' -n '+engine_id+' -p '+load_path+' -i '+keyid

    retval = subprocess.run(cmd, shell=True)
    # should return a failed retval
    return retval != 0

def oesign_detects_failed_key_id(oe_sign_binary:str, enclave:str, config_file:str, engine_id: str, keyid:str, loadpath: str  ) -> int: 
    # ignore keyid
    keyid = 'bogus key'
    cmd = oesign_binary+' sign -e '+enclave+' -c '+config_file+' -n '+engine_id+' -p '+load_path+' -i '+keyid

    retval = subprocess.run(cmd, shell=True)
    # should return a failed retval
    return retval != 0

if __name__ == "__main__":

    test_case = { 'works': oesign_works,
                  'failed-engine-path': oesign_detects_failed_engine_path,
                  'failed-engine-id': oesign_detects_failed_engine_id,
                  'failed-keyid': oesign_detects_failed_key_id }

    arg_parser = argparse.ArgumentParser(description='test cases for oesign engine support' )
    arg_parser.add_argument("command", default=None, type=str, nargs='?', help="oe-sign test", \
                            choices=['failed-keyid', 'failed-engine-id', 'failed-engine-path', 'works']  )
    arg_parser.add_argument("--oesign-binary", default=None, type=str, help="oe-sign binary" )
    arg_parser.add_argument("--enclave-binary", default=None, type=str, help="enclave binary to be signed" )
    arg_parser.add_argument("--config-file", default=None, type=str, help="signing config" )
    arg_parser.add_argument("--engine-id", default=None, type=str, help="openssl engine name" )
    arg_parser.add_argument("--key-id", default=None, type=str, help="openssl engine key identifier" )
    arg_parser.add_argument("--engine-load-path", default=None, type=str, help="openssl engine load path" )

    args = arg_parser.parse_args()
    print(args)

    if not args.command or \
       not args.config_file or \
       not args.enclave_binary or \
       not args.engine_id or \
       not args.engine_load_path or \
       not args.key_id or \
       not args.oesign_binary:

        arg_parser.print_help()
        sys.exit ( 1 )

    retval = test_case[args.command](args.oesign_binary, args.enclave_binary, args.config_file, args.engine_id, args.key_id, args.engine_load_path)
    sys.exit ( retval )
    

