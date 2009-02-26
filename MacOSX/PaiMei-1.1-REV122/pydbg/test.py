#!python

from pydbg import *
    
dbg = pydbg()
    
# register a breakpoint handler function.
dbg.attach(int(sys.argv[1]))
dbg.bp_set(0x00001fdb)    
dbg.debug_event_loop()


#dbg.bp_del(0x00001f96)
#dbg.write_process_memory(0x00001f96, "\xCC")
#dbg.suspend_all_threads()

#for thread_id in dbg.enumerate_threads():
#	context = dbg.get_thread_context(None, thread_id)
#	x = dbg.dump_context(context,0,1);
#	print x
#dbg.read_process_memory(0x00001f96, 32)
#dbg.read_process_memory(2416146071, 1)
#ptrace.VirtualProtectEx(int(sys.argv[1]), 0x90037697,  1,  64)

##print ptrace.EnumerateProcesses()

dbg.detach()

