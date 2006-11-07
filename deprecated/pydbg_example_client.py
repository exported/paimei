#!c:\python\python.exe

#
# PyDBG
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#

'''
@author:       Pedram Amini
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import socket
import cPickle
import thread
import traceback

from pydbg import *
from pydbg.defines import *

hit_count = 0
host      = "10.10.20.104"


def handler_breakpoint (pydbg, dbg, context):
    global hit_count

    if hit_count > 10:
        print "SEH"
        for handler in pydbg.seh_unwind(context):
            print "%08x" % handler

        print "call stack"
        for address in pydbg.stack_unwind(context):
            print "%08x" % address

        pydbg.set_debugger_active(False)
        return DBG_CONTINUE

    hit_count += 1

    exception_code = dbg.u.Exception.ExceptionRecord.ExceptionCode
    print "callback handler hit for %08x" % exception_code

    print pydbg.dump_context()

    return DBG_CONTINUE


def handler_exit_process (pydbg, dbg, context):
    print "debuggee exited"
    thread.exit()


def thread_it_out (arg1, arg2):
    found = False
    dbg   = pydbg_client(host, 7373)

    for (pid, proc) in dbg.enumerate_processes():
        if proc == "test.exe":
            found = True
            break

    if not found:
        print "target proc not found"
        thread.exit()

    print "found proc at %d" % pid

    inline_printf = 0x00403FA0

    try:
        dbg.attach(pid)
        dbg.set_callback(EXCEPTION_BREAKPOINT,     handler_breakpoint)
        dbg.set_callback(EXIT_PROCESS_DEBUG_EVENT, handler_exit_process)
        dbg.bp_set(inline_printf)

        dbg.debug_event_loop()
    except pdx, x:
        if x.__str__() != "connection severed":
            print x.__str__()
            traceback.print_exc()

        thread.exit()
    except:
        print "connection severed"
        thread.exit()


thread.start_new_thread(thread_it_out, (None, None))

import time
while 1:
    time.sleep(5)