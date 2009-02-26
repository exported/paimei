#!python

from pydbg import *
from defines import *
    
def myhandler(pydbg):
	print "Hardware breakpoint"
	#print pydbg.dump_context()
	return DBG_CONTINUE

#
# Can only set a hw bp in a handler (have to have access to a context) 
#
def handler_breakpoint (pydbg):
	print 'Software breakpoint'
	pydbg.bp_set_hw(0x00001fdb, 1, HW_EXECUTE, "", 0, myhandler)
	return DBG_CONTINUE
    
dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x00001fd0,"",0 )
dbg.debug_event_loop()

