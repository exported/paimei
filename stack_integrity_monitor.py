#!c:\python\python.exe

"""
speed ups:
    - replace disasm with byte checks
    - step over rep sequences

turn this:
    [INVALID]:41414141 Unable to disassemble at 41414141 from thread 568 caused access violation when attempting to read from 0x41414141
    
    CONTEXT DUMP
      EIP: 41414141 Unable to disassemble at 41414141
      EAX: 00000001 (         1) -> N/A
      EBX: 0259eedc (  39448284) -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (stack)
      ECX: 00000000 (         0) -> N/A
      EDX: ffffffff (4294967295) -> N/A
      EDI: 00000000 (         0) -> N/A
      ESI: 0259f102 (  39448834) -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (stack)
      EBP: 00000001 (         1) -> N/A
      ESP: 0259e2d4 (  39445204) -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (stack)
      +00: 41414141 (1094795585) -> N/A
      +04: 41414141 (1094795585) -> N/A
      +08: 41414141 (1094795585) -> N/A
      +0c: 41414141 (1094795585) -> N/A
      +10: 41414141 (1094795585) -> N/A
      +14: 41414141 (1094795585) -> N/A
    
    disasm around:
            0x41414141 Unable to disassemble

into this:
    0259fc24: TmRpcSrv.dll.65741721
    0259e7b4: StRpcSrv.dll.65671190
    0259e7a8: Eng50.dll.61181d8c
    0259e790: Eng50.dll.611819a0
    0259e564: Eng50.dll.61181a50
    0259e2d0: Eng50.dll.61190fa4 --> 41414141
    0259e03c: Eng50.dll.61190fd2
    
    STACK INTEGRITY VIOLATON AT: Eng50.dll.61194b8e
    analysis took 35 seconds
"""

import sys
import time
import utils
import pydbgc

from pydbg         import *
from pydbg.defines import *


USAGE = "USAGE: stack_fuck_finder.py <BP ADDR> <PID>"
error = lambda msg: sys.stderr.write("ERROR> " + msg + "\n") or sys.exit(1)


########################################################################################################################
def check_stack_integrity (dbg):
    if not dbg.juju_found:
        for addr, value in dbg.mirror_stack:
            new_value = dbg.flip_endian_dword(dbg.read(addr, 4))

            if new_value != value:
                dbg.juju_found = True

                for a, v in dbg.mirror_stack:
                    if a == addr:
                        print "%08x: %s.%08x --> %08x" % (a, dbg.addr_to_module(v).szModule, v, new_value)
                    else:
                        print "%08x: %s.%08x" % (a, dbg.addr_to_module(v).szModule, v)

                print
                print "STACK INTEGRITY VIOLATON AT: %s.%08x" % (dbg.addr_to_module(dbg.context.Eip).szModule, dbg.context.Eip)
                print "analysis took %d seconds" % (time.time() - dbg.start_time)
                print

                d = pydbgc.PydbgClient(dbg, False)
                d.command_line()

                break


########################################################################################################################
def handler_trace_start (dbg):
    dbg.monitor_tid = dbg.dbg.dwThreadId
    print "starting hit trace on thread %d at 0x%08x" % (dbg.monitor_tid, dbg.context.Eip)
    dbg.single_step(True)

    return DBG_CONTINUE


########################################################################################################################
def handler_breakpoint (dbg):
    if dbg.first_breakpoint:
        return DBG_CONTINUE

    # ignore threads we don't care about that happened to hit one of our breakpoints.
    if dbg.dbg.dwThreadId != dbg.monitor_tid:
        return DBG_CONTINUE

    if dbg.mirror_stack:
        dbg.mirror_stack.pop()

    dbg.single_step(True)
    return DBG_CONTINUE


########################################################################################################################
def handler_single_step (dbg):
    if dbg.dbg.dwThreadId != dbg.monitor_tid:
        return DBG_CONTINUE

    if dbg.juju_found:
        return DBG_CONTINUE

    disasm   = dbg.disasm(dbg.context.Eip)
    ret_addr = dbg.get_arg(0)

    # if the current instruction is in a system DLL and the return address is not, set a breakpoint on it and continue
    # without single stepping.
    if dbg.context.Eip > 0x70000000 and ret_addr < 0x70000000:
        dbg.bp_set(ret_addr)
        return DBG_CONTINUE

    #print "%08x: %s" % (dbg.context.Eip, dbg.disasm(dbg.context.Eip))

    if dbg.mirror_stack and dbg.context.Eip == dbg.mirror_stack[-1][1]:
        dbg.mirror_stack.pop()

    if disasm.startswith("ret"):
        check_stack_integrity(dbg)

    if disasm.startswith("call"):
        dbg.mirror_stack.append((dbg.context.Esp-4, dbg.context.Eip + dbg.instruction.length))

    dbg.single_step(True)
    return DBG_CONTINUE


########################################################################################################################
def handler_access_violation (dbg):
    check_stack_integrity(dbg)

    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)

    print crash_bin.crash_synopsis()
    dbg.terminate_process()


########################################################################################################################
if len(sys.argv) != 3:
    error(USAGE)

try:
    bp_addr = long(sys.argv[1], 16)
    pid     = int(sys.argv[2])
except:
    error(USAGE)

dbg = pydbg()
dbg.mirror_stack = []
dbg.monitor_tid  = 0
dbg.start_time   = time.time()
dbg.juju_found   = False

dbg.set_callback(EXCEPTION_BREAKPOINT,       handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP,      handler_single_step)
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

dbg.attach(pid)
dbg.bp_set(bp_addr, handler=handler_trace_start, restore=False)
print "watching for hit at %08x" % bp_addr
dbg.run()
