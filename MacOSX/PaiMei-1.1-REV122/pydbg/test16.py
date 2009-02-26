#!python

from pydbg import *

value = 0

def handler_badness (pydbg):
	global value
	print "Caused a fault with input %x" % value
        return DBG_EXCEPTION_HANDLED

dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_badness)


dbg.attach(int(sys.argv[1]))
dbg.debug_event_loop()

