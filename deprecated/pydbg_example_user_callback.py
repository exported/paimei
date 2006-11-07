#!c:\python\python.exe

from pydbg import *
from pydbg.defines import *
from msvcrt import kbhit, getch

def user_callback (pydbg):
    if kbhit():
        char = getch()
        print "user_callback() caught key hit on '%c'" % char
        
        if char == 'q':
            pydbg.detach()
            pydbg.set_debugger_active(False)


dbg   = pydbg_client("10.10.20.105", 7373)
found = False

for (pid, name) in dbg.enumerate_processes():
    if name.lower().startswith("calc"):
        found = True
        break

if not found:
    import sys
    print "target process not found"
    sys.exit(1)

try:
    dbg.attach(pid)
    dbg.set_callback(USER_CALLBACK_DEBUG_EVENT, user_callback)
    dbg.debug_event_loop()
except pdx, x:
    dbg.cleanup().detach()
    sys.stderr.write(x.__str__() + "\n")
    