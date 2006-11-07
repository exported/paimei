#!c:\python\python.exe

"""
DEPRECATED: This script was an early prototype for testing in-memory fuzzing capabilities (process snapshot / restore).
The interface to PyDbg is no longer compatible and I have no clue where the companion binary for this thing has gone ;-)
"""

import sys
import getopt
import struct
import traceback

from pydbg import *
from pydbg.defines import *

USAGE = "USAGE: in_mem_fuzz.py <-p|--pid PID>"

# null either of these by setting to lambda x: None
err = lambda msg: sys.stderr.write("ERR> " + msg + "\n") or sys.exit(1)
log = lambda msg: sys.stdout.write("LOG> " + msg + "\n")

# globals.
first_breakpoint  = True
inline_printf     = 0x00403FA0
hit_count         = 0
last_address      = 0

########################################################################################################################
### callback handlers.
########################################################################################################################

def handler_breakpoint (pydbg, dbg, context):
    global first_breakpoint
    global inline_printf
    global hit_count
    global last_address

    # ignore the first windows driven break point.
    if (first_breakpoint):
        first_breakpoint = False
        return DBG_CONTINUE

    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress

    if exception_address == inline_printf:
        log("printf hit %d" % hit_count)

        if hit_count == 3:
            log("taking process snapshot")
            pydbg.process_snapshot()

        if hit_count and hit_count % 6 == 0:
            log("restoring process snapshot")
            pydbg.process_restore()

            if last_address:
                log("free-ing last memory insert at %08x" % last_address)
                pydbg.virtual_free(last_address, 1024, MEM_DECOMMIT)

            address = pydbg.virtual_alloc(None, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
            log("memory allocated at %08x" % address)
            pydbg.write_process_memory(address, "ped"*hit_count)
            log("wrote monikers to allocated memory")
            pydbg.write_process_memory(context.Esp + 0x4, pydbg.flip_endian(address))
            last_address = address

        hit_count += 1

    return DBG_CONTINUE


def handler_access_violation (pydbg, dbg, context):
    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    # disassemble the instruction the exception occured at.
    disasm = pydbg.disasm(exception_address)

    log("************* ACCESS VIOLATION @%08x %s *************" % (exception_address, disasm))

    if write_violation:
        log("violation when attempting to write to %08x" % violation_address)
    else:
        log("violation when attempting to read from %08x" % violation_address)

    mbi = pydbg.virtual_query(violation_address)

    log("page perms of violation address: %08x" % mbi.Protect)

    log(pydbg.dump_context(context))

    pydbg.terminate_process()


########################################################################################################################


# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "p:", ["pid="])
except getopt.GetoptError:
    err(USAGE)

pid = 0

for o, a in opts:
    if o in ("-p", "--pid"): pid = int(a)

if not pid:
    err(USAGE)

pydbg = pydbg()

pydbg.set_callback(EXCEPTION_BREAKPOINT,       handler_breakpoint)
pydbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

try:
    pydbg.attach(pid)

    pydbg.bp_set(inline_printf)

    pydbg.debug_event_loop()
except pdx, x:
    print x.__str__()
    traceback.print_exc()