#!python

from pydbg import *
from defines import *
import time

value = 0

def handler_breakpoint (pydbg):
	global value

	print ">>>>>>>>>>> %x" % pydbg.context.Eip
	# entry to function
	if(pydbg.context.Eip == 0x00001f45):
		pydbg.suspend_all_threads()
		print "-------Taking process snaphost\n"
		pydbg.process_snapshot()
		pydbg.resume_all_threads()
	# exit of function
	elif (pydbg.context.Eip == 0x00001f99) :
		print "-------restoring process snapshot\n"
                pydbg.suspend_all_threads()
		pydbg.process_restore()
		print "The stupid ESP is %x" % pydbg.context.Esp
		addy_to_write_to = pydbg.context.Esp
		addy_to_write_to = addy_to_write_to +4 
		print "Going to write where it says", pydbg.read_process_memory(addy_to_write_to, 4)
		pydbg.write_process_memory(addy_to_write_to, struct.pack('L', value))
		pydbg.resume_all_threads()
		value = value + 1
	else:
		print pydbg.dump_context()
        print "<<<<<<<<<<<  %x" % pydbg.context.Eip
	
	return DBG_CONTINUE
   

dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)

dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x00001f45,"foo-entry",0 )
dbg.bp_set(0x00001f46,"debug",1 )
dbg.bp_set(0x00001f99,"foo-end", 1 )
dbg.debug_event_loop()

