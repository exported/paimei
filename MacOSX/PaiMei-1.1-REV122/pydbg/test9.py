#!python

from pydbg import *
    
dbg = pydbg()
    
dbg.attach(int(sys.argv[1]))

dbg.search_memory("PATH")

dbg.detach()

