#!python

from pydbg import *
    
def handler_breakpoint (pydbg):
	print '--------------------------------Dumping context'
	print pydbg.dump_context()
	return DBG_CONTINUE
    
dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

dbg.attach(int(sys.argv[1]))
dbg.bp_set(int(sys.argv[2], 16),"", 1)

dbg.debug_event_loop()

