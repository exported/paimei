#!c:\python\python.exe

"""
DEPRECATED: See the PAIMEIconsole module instead.
"""

import sys
import getopt
import time
import os

import pida
import utils

from pydbg import *
from pydbg.defines import *

ERR = lambda msg: sys.stderr.write(msg + "\n") & sys.exit(1)

USAGE = """
process stalker 2 (paimei)
pedram amini <pedram.amini@gmail.com>

USAGE:
 process_stalker <-a,attach pid | -l,load filename [--args arguments]>

 options:
   [-b,pida filename]  specify the breakpoint list for the main module.
   [-f,functions-only] stalk functions only.
   [--cc host:#:#]     enable code coverage mode. mysql host:target id:tag id
   [--one-time]        disable breakpoint restoration.
   [--no-regs]         disable register enumeration / dereferencing.
"""

########################################################################################################################

def handler_load_dll (pydbg):
    global pida, o

    last_dll = pydbg.system_dlls[-1]
    print "loading:%s into:%08x size:%d" % (last_dll.name, last_dll.base, last_dll.size)
    
    pida_db = last_dll.name.lower() + ".pida"
    
    if pida_db in [name.lower() for name in os.listdir(".")]:
        start = time.time()
        print "loading %s ..." % pida_db,
        main_module = pida.load(pida_db)
        print "done. completed in %.02f" % (time.time() - start)
        
    return DBG_CONTINUE


def handler_breakpoint (pydbg):
    global pida, o

    if pydbg.first_breakpoint:
        return DBG_CONTINUE

    print "debugger hit %08x" % pydbg.exception_address
    
    if o.has_key("code-coverage"):
        o["code-coverage"].add(pydbg)

    return DBG_CONTINUE


def handler_access_violation (pydbg):
    global pida, o
        
    crash_bin = utils.crash_binning()
    crash_bin.record_crash(pydbg)
    
    print "\n" + crash_bin.crash_synopsis()
    
    pydbg.terminate_process()


########################################################################################################################

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "a:b:fl:", \
        ["args=", "attach=", "-cc=", "functions-only", "load=", "one-time", "pida=", "no-regs"])
except getopt.GetoptError:
    ERR(USAGE)

o = {}

for opt, arg in opts:
    if opt in (      "--args"          ): o["args"]          = arg
    if opt in ("-a", "--attach"        ): o["pid"]           = int(arg)
    if opt in ("--cc"                  ): o["code-coverage"] = arg
    if opt in ("-f", "--functions-only"): o["func-only"]     = True
    if opt in ("-l", "--load"          ): o["load"]          = arg
    if opt in (      "one-time"        ): o["one-time"]      = True
    if opt in ("-b", "--pida"          ): o["pida_db"]       = arg
    if opt in (      "no-regs"         ): o["no-regs"]       = True

if o.has_key("code-coverage"):
    try:
        (host, target_id, tag_id) = o["code-coverage"].split(":")
    
        o["host"]      = host
        o["target_id"] = int(target_id)
        o["tag_id"]    = int(tag_id)
        
        o["code-coverage"] = utils.code_coverage()
    except:
        ERR("invalid code-coverage options: %s\n\n%s" % (o["code-coverage"], USAGE))

if o.has_key("pida_db"):
    start = time.time()
    print "loading %s ..." % o["pida_db"],
    o["main_module"] = pida.load(o["pida_db"])
    print "done. completed in %.02f" % (time.time() - start)

dbg = pydbg()

dbg.set_callback(EXCEPTION_BREAKPOINT,       handler_breakpoint)
dbg.set_callback(LOAD_DLL_DEBUG_EVENT,       handler_load_dll)
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

if   o.has_key("pid"):                        dbg.attach(o["pid"])
elif o.has_key("load") and o.has_key("args"): dbg.load(o["load"], o["args"])
elif o.has_key("load"):                       dbg.load(o["load"])
else:                                         ERR(USAGE)

if o.has_key("main_module"):
    functions = [function.ea_start for function in o["main_module"].nodes.values() if not function.is_import]
    
    if not o.has_key("func-only"):
        basic_blocks = []
        for function in o["main_module"].nodes.values():
            for bb in function.nodes.values():
                basic_blocks.append(bb.ea_start)
    
        if not basic_blocks:
            o["func-only"] = True

    if o.has_key("one-time"):
        restore = False
    else:
        restore = True

    if o.has_key("func-only"):
        print "setting %d bps" % len(functions)
        dbg.bp_set(functions, restore)
    else:
        dbg.bp_set(basic_blocks, restore)

try:
    dbg.debug_event_loop()
except:
    pass
    
print "debugger detached ... exporting code coverage to database."

#o["code-coverage"].export_mysql(o["host"], "root", "", o["target_id"], o["tag_id"])
o["code-coverage"].export_file("c:\\code_coverage.temp")

print "done."