#!python

import pida
    
p = pida.load("Calculator.pida");

for f in p.nodes.values():
	print "Function %s starts at %x and ends at %x" % (f.name, f.ea_start, f.ea_end)
	for bb in f.nodes.values():
		print "     Basic block %x" % bb.ea_start

