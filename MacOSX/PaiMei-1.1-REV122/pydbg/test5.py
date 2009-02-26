#!python

from pydbg import *
from defines import *
    
def handler_breakpoint (pydbg):
	print '--------------------------------Dumping context'
        print pydbg.dump_context()
	return DBG_CONTINUE
    
dbg = pydbg()
    

dbg.attach(int(sys.argv[1]))
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_breakpoint)
dbg.set_callback(EXCEPTION_GUARD_PAGE, handler_breakpoint)

dbg.debug_event_loop()

