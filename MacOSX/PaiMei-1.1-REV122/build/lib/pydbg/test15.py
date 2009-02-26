#!python

from pydbg import *
    
dbg = pydbg()

def handler_breakpoint (pydbg):
	print "Hit!"
	return DBG_CONTINUE
    
# register a breakpoint handler function.
dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x97151330)    
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)



dbg.debug_event_loop()

dbg.detach()

