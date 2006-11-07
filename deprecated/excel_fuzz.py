#!c:\python\python.exe

import random
import time
import thread

import utils

from pydbg import *
from pydbg.defines import *

crash_bin = utils.crash_binning()
crashes   = 0

########################################################################################################################
def access_violation (pydbg, dbg, context):
    global crash_bin, middle, crashes

    crash_bin.record_crash(pydbg, dbg, context, middle)
    
    crashes += 1
    
    if crash_bin.last_crash.exception_address == 0x77c472e3 or 1:
        print
        print crash_bin.crash_synopsis()
        print pydbg.hex_dump(middle)
        print "-" * 60 + "\n"
    else:
        print "ignoring %d\r" % crashes,

    # kill this process.
    pydbg.terminate_process()


def threaded_killer (deadline, pydbg):
    time.sleep(deadline)
    
    try:
        pydbg.terminate_process()
    except:
        pass
        
    return
########################################################################################################################


# open the input file.
fh   = open("excel_fuzz_input.xls", "rb")
orig = fh.read()
fh.close()

print "original length %08x" % len(orig)

top = orig[:0x18fed]

middle = "\xcd\x00\xd4\x00\x12\x12\x00\x08\x0d\x00\x2d\x00\x00\x00\x00\xf6\xc0\xff\xc0\x19"

bottom = orig[0x19001:]

#fh = open("excel_fuzz_output.xls", "wb+")
#fh.write(top+middle+bottom)
#fh.flush()
#fh.close()
#
#sys.exit(1)

print "modified length %08x" % (len(top) + len(middle) + len(bottom))

while 1:
    middle  = "\xcd\x00\xd4\x00\x12\x12"
    #middle += chr(random.randint(0x12, 0x15))
    middle += "\x00\x08\x0d\x00\x2d\x00\x00\x00\x00\xf6\xc0\xff\xc0\x19"
    
    rnd = random.randrange(len(middle))
    mod  = middle[:rnd]
    mod += chr(random.randint(0, 0x3f))
    mod += middle[rnd+1:]
    
    try:
        fh = open("excel_fuzz_output.xls", "wb+")
        fh.write(top+mod+bottom)
        fh.flush()
        fh.close()
    except:
        continue

    dbg = pydbg()
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, access_violation)
    dbg.load("c:\\program files\\microsoft office\\office11\\excel.exe", "excel_fuzz_output.xls")

    thread.start_new_thread(threaded_killer, (1, dbg))

    dbg.debug_event_loop()