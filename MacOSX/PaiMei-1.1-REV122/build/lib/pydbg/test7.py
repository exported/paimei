#!python

from pydbg import *
from defines import *
import pida
import time

def handler_ss (pydbg):
	print "Single stepping"
	print pydbg.dump_context(stack_depth=28)
	return DBG_CONTINUE
    
def handler_breakpoint (pydbg):
	print "-------breakpoint"
	pydbg.single_step(True)
	
	return DBG_CONTINUE

dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
dbg.set_callback(EXCEPTION_SINGLE_STEP, handler_ss)

dbg.attach(int(sys.argv[1]))

dbg.bp_set(0x00001fdb, "", 0)
#dbg.bp_set(0x3d94, "", 0)

dbg.debug_event_loop()

