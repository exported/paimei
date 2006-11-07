#!c:\python\python.exe

"""
todo: someone else really needs to sit down and give my memory breakpoint shit a fresh and new look. the latency can
be drastically reduced if the restoring code can be debugged.

need to make a digestable interface that interlaces the file data and the affected instructions.

need to do some testing against contrived example.

should merge track recv and track file i/o into a tool kit on top of pydbg. the data generation routine can then
be standardized and new tracking items can be easily added.

need to write multi-level mem bp's (after we fix the current bugs)
"""

from pydbg import *
from pydbg.defines import *

import cPickle
import time

from ctypes import *
kernel32 = windll.kernel32
psapi    = windll.psapi

symbols       = {}
ret_addr      = None
mapped_size   = None
last_function = None
handles       = []
handle        = None
buffer        = None
size          = None
mem_bp_hits   = []
snippets      = []

# XXX
snapshot_taken = False
hit_count      = 0

class snippet_struct:
    def __init__ (self):
        self.address = None
        self.raw     = None
        self.handle  = None
    

class mem_bp_hit_struct (memory_breakpoint):
    def __init__ (self):
        self.disasm            = None
        self.write_violation   = None
        self.context           = None
        self.violation_address = None
        self.exception_address = None


########################################################################################################################
def load_dll (pydbg, dbg, context):
    last_dll = pydbg.system_dlls[-1]
    print "loading:%s into:%08x size:%d" % (last_dll.name, last_dll.base, last_dll.size)
    
    return DBG_CONTINUE


########################################################################################################################
def bp_hit (pydbg, dbg, context):
    global symbols, ret_addr, mapped_size, handles, last_function
    global handle, buffer, bytes
    
    # XXX
    global snapshot_taken
    
    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    
    ### MapViewOfFile(Ex) ##############################################################################################
    if exception_address in (symbols["MapViewOfFile"], symbols["MapViewOfFileEx"]):
        ret_addr       = pydbg.get_arg(0, context)
        mapping_object = pydbg.get_arg(1, context)
        mapped_size    = pydbg.get_arg(5, context)

        pydbg.bp_set(ret_addr, restore=False)
        last_function = exception_address

    if exception_address == ret_addr and last_function in (symbols["MapViewOfFile"], symbols["MapViewOfFileEx"]):
        ret_addr = last_function = None
        
        mapped_address = context.Eax
        
        file_name = create_string_buffer(2048)
        psapi.GetMappedFileNameA(pydbg.h_process, mapped_address, byref(file_name), 2048)

        # strip the device path from the file_name.
        try:
            name = "c:\\" + "\\".join(file_name.value.split('\\')[3:])
        except:
            pass

    ### CreateFile(A/W) ################################################################################################
    # XXX - need to add W, and to do so we need a get_unicode_string
    if exception_address == symbols["CreateFileA"]:
        try:
            name_ptr  = pydbg.get_arg(1, context)
            file_name = pydbg.read_process_memory(name_ptr, 255)
            file_name = pydbg.get_ascii_string(file_name)
        except:
            file_name = ""
            ret_addr  = last_function = None
            pass

        if file_name.lower().endswith("mov"):
            # XXX
            if not snapshot_taken:
                print "taking snapshot"
                start = time.time()
                pydbg.process_snapshot()
                print "took %f seconds" % (time.time() - start)
                snapshot_taken = True
                raw_input("hit key to continue.")

            print "CreateFile(%s)" % file_name
            ret_addr = pydbg.get_arg(0, context)
            pydbg.bp_set(ret_addr, restore=False)
            last_function = exception_address


    if exception_address == ret_addr and last_function in (symbols["CreateFileA"], symbols["CreateFileW"]):
        ret_addr = last_function = None
        
        if not handles.count(context.Eax):
            handles.append(context.Eax)
        
        print "CreateFile() == %08x" % context.Eax

    ### ReadFile(Ex) ###################################################################################################
    if exception_address in (symbols["ReadFile"], symbols["ReadFileEx"]):
        ret_addr = pydbg.get_arg(0, context)
        handle   = pydbg.get_arg(1, context)
        buffer   = pydbg.get_arg(2, context)
        bytes    = pydbg.get_arg(3, context)

        if handles.count(handle):
            print "ReadFile(%08x, %08x, %d)" % (handle, buffer, bytes)
            pydbg.bp_set(ret_addr, restore=False)
            last_function = exception_address


    if exception_address == ret_addr and last_function in (symbols["ReadFile"], symbols["ReadFileEx"]):            
        ret_addr = last_function = None

        snippet = snippet_struct()
        snippet.address = buffer
        snippet.handle  = handle
        
        if pydbg.is_address_on_stack(buffer, context):
            print "not setting mem bp on %08x because it lives on the stack" % buffer
        else:
            print "setting a %d byte memory breakpoint at %08x" % (bytes, buffer)

            try:
                snippet.raw = pydbg.read_process_memory(buffer, bytes)
            except:
                snippet.raw = ""
                pass
                
            snippets.append(snippet)
    
            try:
                pydbg.bp_set_mem(buffer, bytes, "handle:%08x" % handle)
            except:
                print "FAILED!"
               

    #pydbg.print_all_mem_bps()
    #print "bp hit routine done."
    return DBG_CONTINUE


########################################################################################################################
def mem_bp_hit (pydbg, dbg, context):
    global mem_bp_hits

    # XXX
    global hit_count
    
    exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    print "memory breakpoint hit from %08x" % exception_address
    #pydbg.print_all_mem_bps()

    # XXX
    hit_count += 1
    if hit_count > 15000:
        pydbg.bp_del_mem_all()
        print "restoring system snapshot"
        start = time.time()
        pydbg.process_restore()
        print "took %f seconds" % (time.time() - start)
        hit_count = 0
        raw_input("hit key to continue.")
    
    # we are only interested in direct buffer hits.
    if not pydbg.memory_breakpoint_hit:
        return DBG_CONTINUE

    print "memory breakpoint belongs to us write=%s at %08x" % (write_violation, violation_address)

    mbh                   = mem_bp_hit_struct()
    mbh.address           = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].address
    mbh.size              = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].size
    mbh.description       = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].description
    mbh.mbi               = pydbg.memory_breakpoints[pydbg.memory_breakpoint_hit].mbi
    mbh.write_violation   = write_violation
    mbh.violation_address = violation_address
    mbh.exception_address = exception_address

    mem_bp_hits.append(mbh)

    return DBG_CONTINUE


########################################################################################################################
### entry point
########################################################################################################################


dbg = pydbg()

dbg.set_callback(LOAD_DLL_DEBUG_EVENT, load_dll)
dbg.set_callback(EXCEPTION_BREAKPOINT, bp_hit)
dbg.set_callback(EXCEPTION_GUARD_PAGE, mem_bp_hit)

for (pid, proc) in dbg.enumerate_processes():
    if proc.lower().startswith("quicktimeplayer"):
        break

symbols["MapViewOfFile"]   = dbg.func_resolve("kernel32", "MapViewOfFile")
symbols["MapViewOfFileEx"] = dbg.func_resolve("kernel32", "MapViewOfFileEx")
symbols["CreateFileA"]     = dbg.func_resolve("kernel32", "CreateFileA")
symbols["CreateFileW"]     = dbg.func_resolve("kernel32", "CreateFileW")
symbols["ReadFile"]        = dbg.func_resolve("kernel32", "ReadFile")
symbols["ReadFileEx"]      = dbg.func_resolve("kernel32", "ReadFileEx")

dbg.attach(pid)
#dbg.load("c:\\program files\\quicktime\\quicktimeplayer.exe")

print "attached."

dbg.bp_set(symbols["MapViewOfFile"])
dbg.bp_set(symbols["MapViewOfFileEx"])
dbg.bp_set(symbols["CreateFileA"])
dbg.bp_set(symbols["ReadFile"])
dbg.bp_set(symbols["ReadFileEx"])

print "breakpoints set, entering debug event loop."

dbg.debug_event_loop()

fh = open("mem_bp_hits.pickle", "w+")
fh.write(cPickle.dumps(mem_bp_hits))
fh.close()

fh = open("snippets.pickle", "w+")
fh.write(cPickle.dumps(snippets))
fh.close()
