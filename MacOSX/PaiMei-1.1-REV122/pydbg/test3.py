#!python

from pydbg import *
from defines import *
import pida
import time
    
def handler_breakpoint (pydbg):
	print "-------breakpoint"
	print "EIP = %x" % pydbg.context.Eip
	return DBG_CONTINUE
   

dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

dbg.attach(int(sys.argv[1]))
p = pida.load("Calculator.pida");

#i = 0;
for f in p.nodes.values():
	addy = f.ea_start
	dbg.bp_set(addy, "", 0)
	print "Setting breakpoint at %x" % addy

dbg.debug_event_loop()

