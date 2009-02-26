#!python

from pydbg import *
from defines import *
    
def myhandler(pydbg):
	print "In my handler"
	print pydbg.dump_context()
	return DBG_CONTINUE
  
def handler_breakpoint (pydbg):
	print '--------------------------------Dumping context'
#	print pydbg.dump_context()
	pydbg.bp_set_hw(0x00001fdb, 1, HW_EXECUTE, "", 0, myhandler)
	return DBG_CONTINUE
    
dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x00001fc3,"",1 )
dbg.debug_event_loop()

