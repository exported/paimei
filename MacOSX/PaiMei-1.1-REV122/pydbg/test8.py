#!python

from pydbg import *
from defines import *
    
def handler_dll (pydbg):
	print '--------------------------------Dumping context'
	print pydbg.dump_context()
	return DBG_CONTINUE
    
dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(LOAD_DLL_DEBUG_EVENT, handler_dll )

dbg.attach(int(sys.argv[1]))

dbg.debug_event_loop()

