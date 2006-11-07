#!c:\python\python.exe

import pydot
import pida
import time
import sys

if len(sys.argv) != 2:
    print "usage: pida_load_example.py <module.pida>"
    sys.exit(1)

print "loading pickled file ... ",
start = time.time()
module = pida.load(sys.argv[1])
print "done. took %.2f seconds" % round(time.time() - start, 3)

print "rendering gml function graph...",
start = time.time()
fh = open("graphs/functions.gml", "w+")
fh.write(module.render_graph_gml())
fh.close()
print "done. took %.2f seconds" % round(time.time() - start, 3)

print "rendering udraw function graph...",
start = time.time()
fh = open("graphs/functions.udg", "w+")
fh.write(module.render_graph_udraw())
fh.close()
print "done. took %.2f seconds" % round(time.time() - start, 3)

#print "rendering dot function graph...",
#start = time.time()
#graph = module.render_graph_graphviz()
#graph.write_png("graphs/functions.png", prog="twopi")
#print "done. took %.2f seconds" % round(time.time() - start, 3)

for function in module.nodes.values():
    if function.ea_start == 0x3702FD30:
        for bb in function.nodes.values():
            print "\t%08x - %08x" % (bb.ea_start, bb.ea_end)
            for ins in bb.instructions.values():
                print "\t\t%s" % ins.disasm

        print "rendering single function graphs...",
        start = time.time()
        fh = open("graphs/function.udg", "w+")
        fh.write(function.render_graph_udraw())
        fh.close()
        fh = open("graphs/function.gml", "w+")
        fh.write(function.render_graph_gml())
        fh.close()
        graph = function.render_graph_graphviz()
        graph.write_png("graphs/function.png", prog="dot")
        print "done. took %.2f seconds" % round(time.time() - start, 3)

    if function.ea_start == 0x004132bc:
        print "rendering proximity graph...",
        start = time.time()
        fh = open("graphs/proximity.udg", "w+")
        prox_graph = module.graph_proximity(function.id, 50, 3)
        fh.write(prox_graph.render_graph_udraw())
        fh.close()
        print "done. took %.2f seconds" % round(time.time() - start, 3)
