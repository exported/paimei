#!c:\python\python.exe

import sys
import getopt
import struct

from pydbg import *
from pydbg.defines import *

USAGE = "USAGE: track_recv.py <-p|--pid PID>"


# null either of these by setting to lambda x: None
err = lambda msg: sys.stderr.write("ERR>   " + msg + "\n") or sys.exit(1)
log = lambda msg: sys.stdout.write("LOG>   " + msg + "\n")
#log = lambda x: None


# globals.
first_breakpoint  = True
winsock_recv      = None
winsock_recvfrom  = None
wsock32_recv      = None
wsock32_recvfrom  = None
mem_bp_hits       = {}


class mem_bp_hit (memory_breakpoint):
    def __init__ (self):
        self.disasm          = None
        self.write_violation = None
        self.context         = None


########################################################################################################################
### callback handlers.
########################################################################################################################


def handler_breakpoint (pydbg, dbg, context):
    global first_breakpoint

    # ignore the first windows driven break point.
    if (first_breakpoint):
        first_breakpoint = False
        return DBG_CONTINUE

    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress

    log("breakpoint handler hit from thread %08x" % dbg.dwThreadId)

    # determine which "hook" we broke on and handle appropriately.
    if exception_address in (winsock_recv, winsock_recvfrom, wsock32_recv, wsock32_recvfrom):
        # ESP                 +4         +8       +C        +10
        # int recv     (SOCKET s, char *buf, int len, int flags)
        # int recvfrom (SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen)
        # we want these:                ^^^      ^^^

        retaddr = pydbg.get_arg(0, context)
        buffer  = pydbg.get_arg(2, context)
        length  = pydbg.get_arg(3, context)

        # set a memory breakpoint on the recv() buffer.
        # XXX - currently limited to heap buffers only as stack buffers would generate a lot of false positives.
        # XXX - need to wrap free to release mem bp's as well.
        # XXX - this obviously won't track user data after it has been copied.
        if exception_address in (winsock_recv, wsock32_recv):
            log("recv(%08x, %d) called from 0x%08x (-1 instr)" % (buffer, length, retaddr))

            if pydbg.is_address_on_stack(buffer, context):
                log("recv() buffer is on stack. ignoring")
            else:
                log("recv() buffer is on heap. setting memory breakpoint.")
                pydbg.bp_set_mem(buffer, length, "recv_%08x" % retaddr)

                # XXX - TRILLIAN test ... freeze all other threads:
                #for thread_id in pydbg.enumerate_threads():
                #    if thread_id != dbg.dwThreadId:
                #        pydbg.suspend_thread(thread_id)

    return DBG_CONTINUE

########################################################################################################################

def handler_memory_breakpoint (pydbg, dbg, context):
    global mem_bp_hits

    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    # we are only interested in direct buffer hits.
    if not pydbg.memory_breakpoint_hit:
        return DBG_CONTINUE

    # ignore instructions we've already seen accessing our data.
    if mem_bp_hits.has_key(exception_address):
        return DBG_CONTINUE

    # disassemble the instruction the exception occured at.
    disasm = pydbg.disasm(exception_address)

    # add the current instruction to the "seen" list.
    mbh                 = mem_bp_hit()
    mbh.disasm          = disasm
    mbh.address         = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].address
    mbh.size            = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].size
    mbh.description     = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].description
    mbh.mbi             = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].mbi
    mbh.write_violation = write_violation
    mbh.context         = pydbg.dump_context(context)

    mem_bp_hits[exception_address] = mbh

    log("MEM BP @%08x %s" % (exception_address, disasm))
    log("%08x -> %s" % (violation_address, pydbg.smart_dereference(violation_address)))

    # we aren't interested in all instruction types.
    # XXX - probably want to research and add more to this list.
    # XXX - other interesting ideas here may include finetuning the intruction set to look for calls perhaps, for the
    #       purpose of creating a sampling of dynamic calls for static analysis.
    if pydbg.instruction.type not in (pydasm.INSTRUCTION_TYPE_MOV,      \
                                      pydasm.INSTRUCTION_TYPE_MOVS,     \
                                      pydasm.INSTRUCTION_TYPE_MOVSX,    \
                                      pydasm.INSTRUCTION_TYPE_MOVZX,    \
                                      pydasm.INSTRUCTION_TYPE_CMP):
        log("ignoring not interesting memory break")
        return DBG_CONTINUE

    return DBG_CONTINUE

########################################################################################################################

def handler_access_violation (pydbg, dbg, context):
    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    # disassemble the instruction the exception occured at.
    disasm = pydbg.disasm(exception_address)

    log("ACCESS VIOLATION @%08x %s" % (exception_address, disasm))

    if write_violation:
        log("violation when attempting to write to %08x" % violation_address)
    else:
        log("violation when attempting to read from %08x" % violation_address)

    try:
        mbi = pydbg.virtual_query(violation_address)
        log("page perms of violation address: %08x" % mbi.Protect)
    except:
        pass

    log(pydbg.dump_context(context))

    pydbg.terminate_process()


########################################################################################################################
### entry point
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
pydbg.set_callback(EXCEPTION_GUARD_PAGE,       handler_memory_breakpoint)
pydbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_access_violation)

try:
    pydbg.attach(pid)

    # resolve the addresses of the functions we want to "hook" and set breakpoints on them.
    winsock_recv     = pydbg.func_resolve("ws2_32",  "recv")
    winsock_recvfrom = pydbg.func_resolve("ws2_32",  "recvfrom")
    wsock32_recv     = pydbg.func_resolve("wsock32", "recv")
    wsock32_recvfrom = pydbg.func_resolve("wsock32", "recvfrom")

    pydbg.bp_set(winsock_recv)
    pydbg.bp_set(winsock_recvfrom)
    pydbg.bp_set(wsock32_recv)
    pydbg.bp_set(wsock32_recvfrom)

    pydbg.debug_event_loop()
except pdx, x:
    pydbg.cleanup().detach()
    sys.stderr.write(x.__str__() + "\n")

print
for address in mem_bp_hits:
    mbh = mem_bp_hits[address]

    if mbh.write_violation:
        direction = "wrote to"
    else:
        direction = "read from"

    print "0x%08x %s %s %08x - %08x [%d]" % (address, mbh.disasm, direction, mbh.address, mbh.address + mbh.size, mbh.size)

    print mbh.context
    print