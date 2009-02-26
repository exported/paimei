#!python

from pydbg import *

value = 0

def handler_badness (pydbg):
	global value
	print "Caused a fault with input %x" % value
        return DBG_EXCEPTION_HANDLED

def handler_breakpoint (pydbg):
	global value

	print ">>>>>>>>>>> %x" % pydbg.context.Eip
	# entry to function
	if(pydbg.context.Eip == 0x00001fbc):
		pydbg.suspend_all_threads()
		print "-------Taking process snaphost\n"
		pydbg.process_snapshot()
		pydbg.resume_all_threads()
	# exit of function
	elif (pydbg.context.Eip == 0x00001ffc) :
		print "-------restoring process snapshot\n"
                pydbg.suspend_all_threads()
		pydbg.process_restore()
		print "The stupid ESP is %x" % pydbg.context.Esp
		addy_to_write_to = pydbg.context.Esp
#		addy_to_write_to = addy_to_write_to + 8
#		print "Going to write where it says", pydbg.read_process_memory(addy_to_write_to, 4)
		pydbg.write_process_memory(addy_to_write_to, struct.pack('L', value))

		pydbg.resume_all_threads()
		value = value + 1
	else:
                pydbg.bp_set(0x00001ffc,"", 0 ) # reset
#		print pydbg.dump_context()



        print "<<<<<<<<<<<  %x" % pydbg.context.Eip
	
	return DBG_CONTINUE
   

dbg = pydbg()
    
# register a breakpoint handler function.
dbg.set_callback(EXCEPTION_BREAKPOINT, handler_breakpoint)
dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, handler_badness)


dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x00001fbc,"",0 )
dbg.bp_set(0x00001fbf,"",1 )
#dbg.bp_set(0x00001ffd,"", 0 ) # failsafe
dbg.debug_event_loop()

