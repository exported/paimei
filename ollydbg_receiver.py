#!c:\python\python.exe

#
# OllyDbg Receiver
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import thread
import sys
import time
import socket
import os
import getopt

import pida
import pgraph
import utils

USAGE = "ollydbg_receiver.py [-h | --host <udraw host>] [-p | --port <udraw port>]"

PURE_PROXIMITY       = 0
PERSISTANT_PROXIMITY = 1
COLOR_VISITED        = 0x0080FF
COLOR_CURRENT        = 0xFF8000

# globals.
udraw                = None
host                 = "0.0.0.0"
port                 = 7033
udraw_host           = "127.0.0.1"
udraw_port           = 2542
modules              = {}
mode                 = PERSISTANT_PROXIMITY
hits                 = []
udraw_call_graph     = None
udraw_cfg            = None
new_graph            = True
last_bb              = 0

########################################################################################################################

def udraw_node_selections_labels (udraw, args):
    print "udraw_node_selections_labels", args


def udraw_node_double_click (udraw, args):
    print "udraw_node_double_click", args

########################################################################################################################

# parse command line options.
try:
    opts, args = getopt.getopt(sys.argv[1:], "h:p:", ["host=","port="])
except getopt.GetoptError:
    sys.stderr.write(USAGE + "\n\n")
    sys.exit(1)

for o, a in opts:
    if o in ("-h", "--host"): udraw_host = a
    if o in ("-p", "--port"): udraw_port = int(a)

try:
    udraw = utils.udraw_connector(udraw_host, udraw_port)
    udraw.set_command_handler("node_double_click",      udraw_node_double_click)
    udraw.set_command_handler("node_selections_labels", udraw_node_selections_labels)
except socket.error, err:
    sys.stderr.write("Socket error: %s.\nIs uDraw(Graph) running on %s:%d?\n" % (err[1], udraw_host, udraw_port))
    sys.exit(1)

# thread out the udraw connector message loop.
thread.start_new_thread(udraw.message_loop, (None, None))

try:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)
except:
    sys.stderr.write("unable to bind to %s:%d\n" % (host, port))
    sys.exit(1)

# accept connections.
while 1:
    print "ollydbg receiver waiting for connection"

    if mode == PURE_PROXIMITY:
        print "mode: pure proximity graphing"
    else:
        print "module: persistant proximity graphing"

    (client, client_address) = server.accept()

    print "client connected."

    # connected client message handling loop.
    while 1:
        try:
            received = client.recv(128)
        except:
            print "connection severed."
            break

        try:
            (module, offset) = received.split(":")

            module = module.lower()
            offset = long(offset, 16)
        except:
            print "malformed data received: '%s'" % received
            continue

        # if we haven't already loaded the specified module, do so now.
        if not modules.has_key(module):
            for name in os.listdir("."):
                name = name.lower()

                if name.startswith(module) and name.endswith(".pida"):
                    start = time.time()
                    print "loading %s ..." % name
                    modules[module] = pida.load(name, progress_bar="ascii")
                    print "done. completed in %.02f" % (time.time() - start)

        # if the module wasn't found, ignore the command.
        if not modules.has_key(module):
            continue

        module  = modules[module]
        ea      = module.base + offset

        # determine which function the address lies in.
        function = module.find_function(ea)

        if not function:
            print "unrecognized address: %08x" % ea
            continue

        # determine which basic block the address lies in.
        bb = module.functions[function.ea_start].find_basic_block(ea)

        if not bb:
            print "unrecognized address: %08x" % ea
            continue

        # if the hit basic block has not already been recorded, do so now.
        if not hits.count(bb.ea_start):
            hits.append(bb.ea_start)

        #
        # CALL GRAPH VIEW
        #

        if function.ea_start == ea:
            # generate new call graph.
            if not udraw_call_graph or mode == PURE_PROXIMITY:
                udraw_call_graph = module.graph_proximity(function.ea_start, 1, 1)

            # add new node and node proximity to current call graph.
            else:
                proximity = module.graph_proximity(function.ea_start, 1, 1)
                proximity.graph_sub(udraw_call_graph)
                udraw_call_graph.graph_cat(proximity)

            current_graph = udraw_call_graph
            new_graph     = True

        #
        # CONTROL FLOW GRAPH VIEW
        #

        else:
            # generate new cfg.
            if not udraw_cfg or not udraw_cfg.find_node("id", bb.ea_start):
                udraw_cfg = module.functions[function.ea_start]
                new_graph = True

            current_graph = udraw_cfg

        # if we in the same graph and in the same basic block, then no graph update is required.
        if not new_graph and bb.ea_start == last_bb:
            continue

        # save the current basic block address as the last bb to be hit.
        last_bb = bb.ea_start

        # color all the previously hit nodes appropriately.
        for ea in current_graph.nodes.keys():
            if hits.count(ea):
                current_graph.nodes[ea].color = COLOR_VISITED

        # color the current node.
        current_graph.nodes[bb.ea_start].color = COLOR_CURRENT

        try:
            print "ea: %08x, bb: %08x, func: %08x" % (ea, bb.ea_start, function.ea_start)

            # XXX - graph updates are not working correctly, so we generate a new graph every time.

            new_graph = False
            udraw.graph_new(current_graph)

            #if new_graph:
            #    udraw.graph_new(current_graph)
            #    new_graph = False
            #else:
            #    udraw.graph_update(current_graph)

            udraw.window_title(function.name)
            udraw.change_element_color("node", bb.ea_start, COLOR_CURRENT)
            udraw.focus_node(bb.ea_start, animated=True)
        except:
            print "connection severed."
            break