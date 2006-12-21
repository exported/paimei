#
# PIDA Basic Block
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
@author:       Pedram Amini, Cameron Hotchkies
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import pgraph
from sql_singleton  import *
from instruction    import *
from defines        import *

class basic_block (pgraph.node):
    '''
    '''

    __cached         = False
    __ea_start       = None
    __ea_end         = None
    function         = None
    module           = None
    instructions     = {}
    
    dbid             = None     # Database ID
    
    ext              = {}
    database_file    = None

    ####################################################################################################################
    def __init__ (self, database_id, database_file):
        '''
        Analyze the basic block from ea_start to ea_end.

        @see: defines.py

        @type  ea_start: DWORD
        @param ea_start: Effective address of start of basic block (inclusive)
        @type  ea_end:   DWORD
        @param ea_end:   Effective address of end of basic block (inclusive)
        @type  depth:    Integer
        @param depth:    (Optional, Def=DEPTH_FULL) How deep to analyze the module
        @type  analysis: Integer
        @param analysis: (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
        @type  function: pida.function
        @param function: (Optional, Def=None) Pointer to parent function container
        '''

        # TODO
        # run the parent classes initialization routine first.
        # super(basic_block, self).__init__(ea_start)

        self.dbid = database_id
        self.database_file = database_file

    ####################################################################################################################
    def __load_from_sql(self):
        ss = sql_singleton()
        cr = ss.connection(self.database_file).cursor()
        sql = "SELECT module, function, start_address, end_address FROM basic_block WHERE id = %d;" % self.dbid
        cr.execute(sql)
        
        results = cr.fetchone()
        
        self.module     = results[0]
        self.function   = results[1]       
        self.__ea_start = results[2]
        self.__ea_end   = results[3]

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
        curs = ss.connection(self.database_file).cursor()
        curs.execute("UPDATE basic_block SET start_address=%d where id=%d" % (value, self.dbid))
        ss.connection().commit()
    
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
        curs = ss.connection(self.database_file).cursor()
        curs.execute("UPDATE basic_block SET end_address=%d where id=%d" % (value, self.dbid))
        ss.connection().commit()
        
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
        cr = ss.connection(self.database_file).cursor()
        sql = "SELECT count(*) FROM instruction WHERE basic_block = %d;" % self.dbid
        cr.execute(sql)
        
        try:
            ret_val = cr.fetchone()[0]
        except:
            ret_val = 0
            
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
        Return a list of the instructions within the graph, sorted by id.

        @rtype:  List
        @return: List of instructions, sorted by id.
        '''

        ret_val = []
        ss = sql_singleton()
        
        cursor = ss.connection(self.database_file).cursor()
        
        results = cursor.execute("SELECT id FROM instruction WHERE basic_block = %d" % self.dbid).fetchall()
        
        for instruction_id in results:
            new_instruction = instruction(instruction_id[0], self.database_file)
            ret_val.append(new_instruction)
            
        return ret_val       
        
    ####################################################################################################################
    # PROPERTIES
    
    num_instructions = property(__getNumInstructions,   __setNumInstructions,   __deleteNumInstructions,    "num_instructions")
    ea_start         = property(__getEaStart,           __setEaStart,           __deleteEaStart,            "ea_start")
    ea_end           = property(__getEaEnd,             __setEaEnd,             __deleteEaEnd,              "ea_end")
