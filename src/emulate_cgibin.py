#!/usr/bin/env python3
#  
# This simple scripts emulates the cgibin binary
# part of the DIR645A1_FW103RUB08 firmware for
# TPLINK DIR-645 Router.
# cgibin binary is affected by several vulnerabilities
# More information: 

import argparse
import sys
sys.path.append("..")

from capstone import *
from qiling import *
from qiling.const import *
from unicorn import *


MAIN = 0x0402770
HEDWINCGI_MAIN_ADDR = 0x0040bfc0
SESS_GET_UID = 0x004083f0

md = Cs(CS_ARCH_MIPS, CS_MODE_32 + CS_MODE_LITTLE_ENDIAN)

def hook_sess_get_uid(ql):
    ql.hook_code(print_asm)

def strcpy_hook(ql):
    print("dst: %s" % hex(ql.os.function_arg[0]))
    print("src: %s" % ql.mem.string(ql.os.function_arg[1]))

    #Not sure why I have to return 2 to continue with the call
    #to the strcpy function. This was taken from example:
    #hello_mips32el_linux_function_hook.py
    return 2

# From https://github.com/qilingframework/qiling/blob/master/examples/hello_x8664_linux_disasm.py
def print_asm(ql, address, size):
    buf = ql.mem.read(address, size)
    for i in md.disasm(buf, address):
        print(":: 0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def my_sandbox(path, rootfs):
    #buffer = "uid=%s" % (b"A" * 1041 + b"1111")
    buffer = "uid=%s" % (b"A" * 2000)
    #buffer = "uid=%s" % (b"A" * 5)
    required_env = {
        "REQUEST_METHOD": "POST",
        "HTTP_COOKIE"   : buffer
    }

    ql = Qiling(path, rootfs, output = "none", env=required_env)
    ql.add_fs_mapper('/tmp', '/var/tmp')                              # Maps hosts /tmp to /var/tmp
    ql.hook_address(lambda ql: ql.nprint("** At [main] **"), MAIN)
    ql.hook_address(lambda ql: ql.nprint("** At [hedwingcgi_main] **"), HEDWINCGI_MAIN_ADDR)
    ql.hook_address(lambda ql: ql.nprint("** At [sess_get_uid] **"), SESS_GET_UID)
    ql.hook_address(lambda ql: ql.nprint("** Ret from sobj_add_string **"), 0x004085c4)
    ql.set_api('strcpy', strcpy_hook, QL_INTERCEPT.ENTER)
    #ql.debugger = True
    ql.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('PathToCgibin',
                    help='Path to cgibin binary')
    parser.add_argument('PathToRootFs',
                help="Path to root fs")
    args = parser.parse_args()
    my_sandbox([args.PathToCgibin], args.PathToRootFs)
