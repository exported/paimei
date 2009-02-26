#!python

from pydbg import *
from defines import *
import time

counter = 0;
    
def handler_breakpoint (pydbg):
	global counter
	print "Eax: %x" % pydbg.context.Eax
	if(counter==0):
		pydbg.suspend_all_threads()
		print "-------Taking process snaphost"
		pydbg.process_snapshot()
		print "-------Done taking snapshot"
		pydbg.resume_all_threads()
		print "-------All threads resumed"
	if(counter == 7):
		pydbg.suspend_all_threads()
		print "-------restoring process snapshot"
		pydbg.process_restore()
		pydbg.resume_all_threads()
	counter = counter + 1
	return DBG_CONTINUE
   

dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x00001fdb,"",1 )

dbg.debug_event_loop()

