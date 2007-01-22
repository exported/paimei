#
# PIDA Basic Block
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
# Copyright (C) 2007 Cameron Hotchkies <chotchkies@tippingpoint.com>
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

import pgraph
from sql_singleton  import *
from instruction    import *
from defines        import *

class basic_block (pgraph.node):
    '''
    A basic block instruction container.
    
    @author:        Cameron Hotchkies, Pedram Amini
    @license:       GNU General Public License 2.0 or later
    @contact:       chotchkies@tippingpoint.com
    @organization:  www.openrce.org
    
    @cvar dbid:     Database Identifier
    @type dbid:     Integer
    @cvar DSN:      Database location
    @type DSN:      String    
    '''

    __cached         = False
    __ea_start       = None
    __ea_end         = None

    # Database IDs
    function         = None
    module           = None
    dbid             = None
    DSN              = None

    ext              = {}

    ####################################################################################################################
    def __init__ (self, DSN, database_id):
        '''
        Initializes a basic block instance.

        @type  DSN:         String
        @param DSN:         The data source for the basic block to draw from.
        @type  database_id: Integer
        @param database_id: The record ID of the basic block.
        '''

        # TODO
        # run the parent classes initialization routine first.
        # super(basic_block, self).__init__(ea_start)

        self.dbid = database_id
        self.DSN = DSN

    ####################################################################################################################
    def __load_from_sql(self):
        ss = sql_singleton()
        results = ss.select_basic_block(self.DSN, self.dbid)
        
        self.module     = results['module']
        self.function   = results['function']
        self.__ea_start = results['start_address']
        self.__ea_end   = results['end_address']

        self.__cached = True

    ####################################################################################################################
    # ea_start accessors

    def __getEaStart (self):
        '''
        Gets the starting address of the basic block.

        @rtype:  DWORD
        @return: The starting address of the basic block.
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__ea_start

    ####

    def __setEaStart (self, value):
        '''
        Sets the starting address of the basic block.

        @type  value: DWORD
        @param value: The starting address of the basic block.
        '''

        if self.__cached:
            self.__ea_start = value

        ss = sql_singleton()
        ss.update_basic_block_start_address(self.DSN, self.dbid, value)
        
    ####

    def __deleteEaStart (self):
        '''
        destructs the starting address of the basic block
        '''
        del self.__ea_start

    ####################################################################################################################
    # ea_end accessors

    def __getEaEnd (self):
        '''
        Gets the ending address of the basic block.

        @rtype:  DWORD
        @return: The ending address of the basic block.
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__ea_end

    ####

    def __setEaEnd (self, value):
        '''
        Sets the ending address of the basic block.

        @type  value: DWORD
        @param value: The ending address of the basic block.
        '''

        if self.__cached:
            self.__ea_end = value

        ss = sql_singleton()
        ss.update_basic_block_end_address(self.DSN, self.dbid, value)
        
    ####

    def __deleteEaEnd (self):
        '''
        destructs the ending address of the basic block
        '''
        del self.__ea_end

    ####################################################################################################################
    # num_instructions accessors

    def __getNumInstructions (self):
        '''
        Gets the number of instructions in the basic block.

        @rtype:  Integer
        @return: The number of instructions in the basic block.
        '''

        ss = sql_singleton()
        ret_val = ss.select_basic_block_num_instructions(self.DSN, self.dbid)
        
        return ret_val

    ####

    def __setNumInstructions (self, value):
        '''
        Sets the number of instructions in the basic block. (This will raise an exception as this is read-only)

        @type  value: Integer
        @param value: The number of instructions in the basic block.
        '''

        raise TypeError, "The num_instructions property is read-only"

    ####

    def __deleteNumInstructions (self):
        '''
        destructs the number of instructions in the basic block
        '''
        pass # dynamically generated property value

    ####################################################################################################################
    # nodes accessors

    def __getNodes (self):
        '''
        Gets the instructions in the basic block.

        @rtype:  [pida.instruction]
        @return: The instructions in the basic block.
        '''

        # FIX TODO: should be a dict!
        
        return self.sorted_instructions()

    ####

    def __setNodes (self, value):
        '''
        Sets the instructions in the basic block. (This will raise an exception as this is read-only)

        @type  value: [pida.instruction]
        @param value: The number of instructions in the basic block.
        '''

        raise TypeError, "The nodes property is read-only"

    ####

    def __deleteNodes (self):
        '''
        destructs the instructions in the basic block
        '''
        pass # dynamically generated property value

    ####################################################################################################################
    # instructions accessors

    def __getInstructions (self):
        '''
        Gets the instructions in the basic block.

        @rtype:  [pida.instruction]
        @return: The instructions in the basic block.
        '''

        ins = self.sorted_instructions()

        ret_val = {}

        for i in ins:
            ret_val[i.address] = i

        return ret_val

    ####

    def __setInstructions (self, value):
        '''
        Sets the instructions in the basic block. (This will raise an exception as this is read-only)

        @type  value: [pida.instruction]
        @param value: The number of instructions in the basic block.
        '''

        raise TypeError, "The nodes property is read-only"

    ####

    def __deleteInstructions (self):
        '''
        destructs the instructions in the basic block
        '''
        pass # dynamically generated property value

    ####################################################################################################################

    def overwrites_register (self, register):
        '''
        Indicates if the given register is modified by this block.

        @type  register: String
        @param register: The text representation of the register

        @rtype:  Boolean
        @return: True if the register is modified by any instruction in this block.
        '''

        for ins in self.instructions.values():
            if ins.overwrites_register(register):
                return True

        return False

    ####################################################################################################################
    def render_node_gml (self, graph):
        '''
        Overload the default node.render_node_gml() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label  = "<span style='font-family: Courier New; font-size: 10pt; color: #000000'>"
        self.label += "<p><font color=#004080><b>%08x</b></font></p>" % self.ea_start

        self.gml_height = 45

        for instruction in self.sorted_instructions():
            colored_instruction = instruction.disasm.split()

            if colored_instruction[0] == "call":
                colored_instruction[0] = "<font color=#FF8040>" + colored_instruction[0] + "</font>"
            else:
                colored_instruction[0] = "<font color=#004080>" + colored_instruction[0] + "</font>"

            colored_instruction = " ".join(colored_instruction)

            self.label += "<font color=#999999>%08x</font>&nbsp;&nbsp;%s<br>" % (instruction.ea, colored_instruction)

            try:    instruction_length = len(instruction.disasm)
            except: instruction_length = 0

            try:    comment_length = len(instruction.comment)
            except: comment_length = 0

            required_width = (instruction_length + comment_length + 10) * 10

            if required_width > self.gml_width:
                self.gml_width = required_width

            self.gml_height += 20

        self.label += "</span>"

        return super(basic_block, self).render_node_gml(graph)


    ####################################################################################################################
    def render_node_graphviz (self, graph):
        '''
        Overload the default node.render_node_graphviz() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @type  graph: pgraph.graph
        @param graph: Top level graph object containing the current node

        @rtype:  pydot.Node()
        @return: Pydot object representing node
        '''

        self.label = ""
        self.shape = "box"

        for instruction in self.sorted_instructions():
            self.label += "%08x  %s\\n" % (instruction.ea, instruction.disasm)

        return super(basic_block, self).render_node_graphviz(graph)


    ####################################################################################################################
    def render_node_udraw (self, graph):
        '''
        Overload the default node.render_node_udraw() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @type  graph: pgraph.graph
        @param graph: Top level graph object containing the current node

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label = ""

        for instruction in self.sorted_instructions():
            self.label += "%08x  %s\\n" % (instruction.ea, instruction.disasm)

        return super(basic_block, self).render_node_udraw(graph)


    ####################################################################################################################
    def render_node_udraw_update (self):
        '''
        Overload the default node.render_node_udraw_update() routine to create a custom label. Pass control to the
        default node renderer and then return the merged content.

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label = ""

        for instruction in self.sorted_instructions():
            self.label += "%08x  %s\\n" % (instruction.ea, instruction.disasm)

        return super(basic_block, self).render_node_udraw_update()


    ####################################################################################################################
    def sorted_instructions (self):
        '''
        Return a list of the instructions within the basic block, sorted by address.

        @rtype:  List
        @return: List of instructions, sorted by id.
        '''

        ret_val = []
        ss = sql_singleton()
        results = ss.select_basic_block_sorted_instructions(self.DSN, self.dbid)
        
        for instruction_id in results:
            new_instruction = instruction(self.DSN, instruction_id)
            ret_val.append(new_instruction)

        return ret_val

    ####################################################################################################################
    # PROPERTIES

    num_instructions    = property(__getNumInstructions,    __setNumInstructions,   __deleteNumInstructions,    "The number of instructions in the basic block.")
    ea_start            = property(__getEaStart,            __setEaStart,           __deleteEaStart,            "The starting address of the basic block.")
    ea_end              = property(__getEaEnd,              __setEaEnd,             __deleteEaEnd,              "The ending address of the basic block.")
    nodes               = property(__getNodes,              __setNodes,             __deleteNodes,              "The instructions in the basic block keyed by address.")
    instructions        = property(__getInstructions,       __setInstructions,      __deleteInstructions,       "The instructions in the basic block keyed by address.")
    id                  = property(__getEaStart,            __setEaStart,           __deleteEaStart,            "The basic block id (internal use only)")