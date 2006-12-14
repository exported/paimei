#
# PIDA Function
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

from sql_singleton import *

from basic_block import *
from defines     import *

class function (pgraph.graph, pgraph.node):
    '''
    '''
    dbid                = None
    __cached            = False

    __ea_start          = None
    __ea_end            = None
    __name              = None
    __is_import         = False
    __flags             = None

    # TODO: implement RPC functionality
    __rpc_cache         = False
    __rpc_uuid          = None
    __rpc_opcode        = None
                        
    # Frame info        
    __frame_info_cache  = False
    __saved_reg_size    = 0
    __frame_size        = 0
    __ret_size          = 0
    __local_var_size    = 0
    __arg_size          = 0

    # GHETTO - we want to store the actual function to function edge start address.
    outbound_eas        = {}
                        
    module              = None
                        
    id                  = None
                        
    local_vars          = {}                       
    args                = {}
                        
    # is this runtime only?
    chunks              = []
                       
    ext                 = {}    

    ####################################################################################################################
    def __init__ (self, database_id):
        '''
        Analyze all the function chunks associated with the function starting at ea_start.
        self.fill(ea_start).

        @see: defines.py

        @type  ea_start: DWORD
        @param ea_start: Effective address of start of function (inclusive)
        @type  depth:    Integer
        @param depth:    (Optional, Def=DEPTH_FULL) How deep to analyze the module
        @type  analysis: Integer
        @param analysis: (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
        @type  module:   pida.module
        @param module:   (Optional, Def=None) Pointer to parent module container
        '''

        dbid = database_id

    ####################################################################################################################
    def __load_from_sql(self):
        ss = sql_singleton()
        cr = ss.cursor()
        sql = "SELECT * FROM function WHERE id = %d;" % self.dbid
        cr.execute(sql)
        
        results = cr.fetchall()
        
        print results


    ####################################################################################################################
    def __init_collect_function_chunks__ (self):
        '''
        Generate and return the list of function chunks (including the main one) for the current function. Ripped from
        idb2reml (Ero Carerra).

        @rtype   List
        @return: List of function chunks (start, end tuples) for the current function.
        '''

        chunks   = []
        iterator = func_tail_iterator_t(get_func(self.ea_start))
        status   = iterator.main()

        while status:
            chunk = iterator.chunk()
            chunks.append((chunk.startEA, chunk.endEA))
            status = iterator.next()

        return chunks


  
    ####################################################################################################################
    # num_instruction
    
    def getNumInstructions (self):
        '''
        The number of instructions in the function
        
        @rtype:  Integer
        @return: The number of instructions in the function
        '''
        
        ss = sql_singleton()
        cr = ss.cursor()
        sql = "SELECT count(*) FROM instruction WHERE function = %d;" % self.dbid
        cr.execute(sql)
        
        try:
            ret_val = cr.fetchone()[0]
        except:
            ret_val = 0
            
        return ret_val
        
    ####
    
    def setNumInstructions (self, value):
        '''
        Sets the number of instructions (raises an exception - READ ONLY)
        
        @type  value: Integer
        @param value: The number of instructions in the function
        '''
        raise TypeError, "num_instructions is a read-only property"
        return -1
    
    ####
        
    def deleteNumInstructions (self):
        '''
        destructs the num_instructions
        '''
        pass # dynamically generated property value

    ####################################################################################################################
    # ea_start accessors
    
    def getEaStart (self):
        '''
        Gets the starting address of the function.
        
        @rtype:  DWORD
        @return: The starting address of the function
        '''
        
        if not self.__cached:
            self.load_from_sql()            
            
        return self.__ea_start
        
    ####
    
    def setEaStart (self, value):
        '''
        Sets the starting address of the function
        
        @type  value: DWORD
        @param value: The starting address of the function
        '''
        
        if self.__cached:
            self.__ea_start = value
            
        ss = sql_singleton()                        
        ss.cursor().execute("UPDATE function SET start_address=%d where id=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteEaStart (self):
        '''
        destructs the address of the function
        '''
        del __ea_start

    ####################################################################################################################
    # ea_end accessors
    
    def getEaEnd (self):
        '''
        The ending address of the function. This should not be treated as an absolute due to function chunking.
        
        @rtype:  DWORD
        @return: The ending address of the function
        '''
        
        if not self.__cached:
            self.load_from_sql()
            
        return self.__ea_end
        
    ####
    
    def setEaEnd (self, value):
        '''
        Sets the ending address of the function
        
        @type  value: DWORD
        @param value: The ending address of the function
        '''
        
        if self.__cached:
            self.__ea_end = value
            
        ss = sql_singleton()                        
        ss.cursor().execute("UPDATE function SET end_address=%d where id=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteEaEnd (self):
        '''
        destructs the ending address of the function
        '''
        del self.__ea_end
        
    ####################################################################################################################
    # name accessors
    
    def getName (self):
        '''
        Gets the name of the function.
        
        @rtype:  String
        @return: The name of the function.
        '''
        
        if not self.__cached:
            self.load_from_sql()
            
        return self.__name
        
    ####
    
    def setName (self, value):
        '''
        Sets the name of the function.
        
        @type  value: String
        @param value: The name of the function.
        '''
        
        if self.__cached:
            self.__name = value
            
        ss = sql_singleton()                        
        ss.cursor().execute("UPDATE function SET name='%s' where id=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteName (self):
        '''
        destructs the name of the function
        '''
        del self.__name     

    ####################################################################################################################
    # is_import accessors
    
    def getIsImport (self):
        '''
        Gets the indicator if the function is an import.
        
        @rtype:  Boolean
        @return: The indicator if the function is an import.
        '''
        
        if not self.__cached:
            self.load_from_sql()
            
        return __is_import
        
    ####
    
    def setIsImport (self, value):
        '''
        Sets the indicator if the function is an import.
        
        @type  value: Boolean
        @param value: The indicator if the function is an import.
        '''
        
        raise TypeError, "is_import is a read-only property"
        return -1
    
    ####
        
    def deleteIsImport (self):
        '''
        destructs the indicator if the function is an import
        '''
        del __is_import 
        
    ####################################################################################################################
    # flags accessors
    
    def getFlags (self):
        '''
        Gets the function flags.
        
        @rtype:  Unknown
        @return: The function flags.
        '''
        
        if not self.__cached:
            self.load_from_sql()
            
        return self.__flags
        
    ####
    
    def setFlags (self, value):
        '''
        Sets the function flags.
        
        @type  value: Unknown
        @param value: The function flags.
        '''
        
        if self.__cached:
            self.__flags = value
            
        ss = sql_singleton()                        
        
        ss.cursor().execute("UPDATE function SET flags=%d where id=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteFlags (self):
        '''
        destructs the function flags
        '''
        del self.__flags 

    ####################################################################################################################
    # saved_reg_size accessors
    
    def getSavedRegSize (self):
        '''
        Gets the saved register size.
        
        @rtype:  Integer
        @return: The saved register size.
        '''
        
        if not self.__frame_info_cache:            
            self.load_frame_info_from_sql()
            
        return self.__saved_reg_size
        
    ####
    
    def setSavedRegSize (self, value):
        '''
        Sets the saved register size.
        
        @type  value: Integer
        @param value: The saved register size.
        '''
        
        if self.__frame_info_cache:
            self.__saved_reg_size = value
            
        ss = sql_singleton()                        
        
        ss.cursor().execute("UPDATE frame_info SET saved_reg_size=%d where function=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteSavedRegSize (self):
        '''
        destructs the saved register size
        '''
        del self.__saved_reg_size 
        
    ####################################################################################################################
    # frame_size accessors
    
    def getFrameSize (self):
        '''
        Gets the frame size.
        
        @rtype:  Integer
        @return: The frame size.
        '''
        
        if not self.__frame_info_cache:
            #TODO: call SQL load
            pass
            
        return self.__frame_size
        
    ####
    
    def setFrameSize (self, value):
        '''
        Sets the frame size.
        
        @type  value: Integer
        @param value: The frame size.
        '''
        
        if self.__frame_info_cache:
            self.__frame_size = value
            
        ss = sql_singleton()                        
        
        ss.cursor().execute("UPDATE frame_info SET frame_size=%d where function=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteFrameSize (self):
        '''
        destructs the frame size
        '''
        del self.__frame_size 

    ####################################################################################################################
    # ret_size accessors
    
    def getRetSize (self):
        '''
        Gets the return size.
        
        @rtype:  Integer
        @return: The return size.
        '''
        
        if not self.__frame_info_cache:
            #TODO: call SQL load
            pass
            
        return self.__ret_size
        
    ####
    
    def setRetSize (self, value):
        '''
        Sets the return size.
        
        @type  value: Integer
        @param value: The return size.
        '''
        
        if self.__frame_info_cache:
            self.__ret_size = value
            
        ss = sql_singleton()                        
        
        ss.cursor().execute("UPDATE frame_info SET ret_size=%d where function=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteRetSize (self):
        '''
        destructs the return size
        '''
        del self.__ret_size 

    ####################################################################################################################
    # local_var_size accessors
    
    def getLocalVarSize (self):
        '''
        Gets the local variable frame size.
        
        @rtype:  Integer
        @return: The local variable frame size.
        '''
        
        if not self.__frame_info_cache:
            #TODO: call SQL load
            pass
            
        return self.__local_var_size
        
    ####
    
    def setLocalVarSize (self, value):
        '''
        Sets the local variable frame size.
        
        @type  value: Integer
        @param value: The local variable frame size.
        '''
        
        if self.__frame_info_cache:
            self.__local_var_size = value
            
        ss = sql_singleton()                        
        
        ss.cursor().execute("UPDATE frame_info SET local_var_size=%d where function=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteLocalVarSize (self):
        '''
        destructs the local variable frame size
        '''
        del self.__local_var_size 

    ####################################################################################################################
    # arg_size accessors
    
    def getArgSize (self):
        '''
        Gets the argument frame size.
        
        @rtype:  Integer
        @return: The argument frame size.
        '''
        
        if not self.__frame_info_cache:
            #TODO: call SQL load
            pass
            
        return self.__arg_size
        
    ####
    
    def setArgSize (self, value):
        '''
        Sets the argument frame size.
        
        @type  value: Integer
        @param value: The argument frame size.
        '''
        
        if self.__frame_info_cache:
            __arg_size = value
            
        ss = sql_singleton()                        
        
        ss.cursor().execute("UPDATE frame_info SET arg_size=%d where function=%d" % (value, self.dbid))
        ss.connection().commit()
    
    ####
        
    def deleteArgSize (self):
        '''
        destructs the argument frame size
        '''
        del self.__arg_size 
        
    ####################################################################################################################
    # num_local_vars accessors
    
    def getNumLocalVars (self):
        '''
        Gets the number of local variables.
        
        @rtype:  Integer
        @return: The number of local variables.
        '''
        
        ss = sql_singleton()                        
        
        ret_val = ss.cursor().execute("SELECT count(*) FROM function_variables WHERE function = %d AND flags & %d > 0" % (self.dbid, VAR_TYPE_LOCAL)).fetchone()[0]
              
        return ret_val
        
    ####
    
    def setNumLocalVars (self, value):
        '''
        Sets the number of local variables. (will raise an exception, this is a READ-ONLY property)
        
        @type  value: Integer
        @param value: The number of local variables.
        '''
        
        raise TypeError, "num_local_vars is a read-only property"
    
    ####
        
    def deleteNumLocalVars (self):
        '''
        destructs the number of local variables
        '''
        pass # dynamically generated property value
        
    ####################################################################################################################
    # num_args accessors
    
    def getNumArgs (self):
        '''
        Gets the number of function arguments.
        
        @rtype:  Integer
        @return: The number of function arguments.
        '''
        
        ss = sql_singleton()                        
        
        ret_val = ss.cursor().execute("SELECT count(*) FROM function_variables WHERE function = %d AND flags & %d > 0" % (self.dbid, VAR_TYPE_ARG)).fetchone()[0]
              
        return ret_val
        
    ####
    
    def setNumArgs (self, value):
        '''
        Sets the number of function arguments.
        
        @type  value: Integer
        @param value: The number of function arguments.
        '''
        
        raise TypeError, "num_args is a read-only property"
    
        
    ####
        
    def deleteNumArgs (self):
        '''
        destructs the number of function arguments
        '''
        pass # dynamically generated property value 


    ####################################################################################################################
    def find_basic_block (self, ea):
        '''
        Locate and return the basic block that contains the specified address.

        @type  ea: DWORD
        @param ea: An address within the basic block to find

        @rtype:  pida.basic_block
        @return: The basic block that contains the given address or None if not found.
        '''

        for bb in self.nodes.values():
            if bb.ea_start <= ea <= bb.ea_end:
                return bb

        return None


    ####################################################################################################################
    def render_node_gml (self, graph):
        '''
        Overload the default node.render_node_gml() routine to create a custom label. Pass control to the default
        node renderer and then return the merged content.

        @type  graph: pgraph.graph
        @param graph: Top level graph object containing the current node

        @rtype:  String
        @return: Contents of rendered node.
        '''

        self.label  = "<span style='font-family: Courier New; font-size: 10pt; color: #000000'>"
        self.label += "<p><font color=#004080><b>%08x %s</b></font></p>" % (self.ea_start, self.name)

        self.gml_height = 100
        self.gml_width  = (len(self.name) + 10) * 10

        if not self.is_import:
            self.label += "<b>size</b>: <font color=#FF8040>%d</font><br>" % (self.ea_end - self.ea_start)
            self.label += "<b>arguments</b>:<br>"

            for key, arg in self.args.items():
                self.label += "&nbsp;&nbsp;&nbsp;&nbsp;[%02x]%s<br>" % (key, arg)

                required_width = (len(arg) + 10) * 10

                if required_width > self.gml_width:
                    self.gml_width = required_width

                self.gml_height += 20

            self.label += "<b>local variables</b>:<br>"

            for key, var in self.local_vars.items():
                self.label += "&nbsp;&nbsp;&nbsp;&nbsp;[%02x] %s<br>" % (key, var)

                required_width = (len(var) + 10) * 10

                if required_width > self.gml_width:
                    self.gml_width = required_width

                self.gml_height += 20

        self.label += "</span>"

        return super(function, self).render_node_gml(graph)


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

        self.shape = "ellipse"

        if self.is_import:
            self.label = "%s" % (self.name)
        else:
            self.label  = "%08x %s\\n" % (self.ea_start, self.name)
            self.label += "size: %d"   % (self.ea_end - self.ea_start)

        return super(function, self).render_node_graphviz(graph)


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

        if self.is_import:
            self.label = "%s" % (self.name)
        else:
            self.label  = "%08x %s\\n" % (self.ea_start, self.name)
            self.label += "size: %d"   % (self.ea_end - self.ea_start)

        return super(function, self).render_node_udraw(graph)


    ####################################################################################################################
    def render_node_udraw_update (self):
        '''
        Overload the default node.render_node_udraw_update() routine to create a custom label. Pass control to the
        default node renderer and then return the merged content.

        @rtype:  String
        @return: Contents of rendered node.
        '''

        if self.is_import:
            self.label = "%s" % (self.name)
        else:
            self.label  = "%08x %s\\n" % (self.ea_start, self.name)
            self.label += "size: %d"   % (self.ea_end - self.ea_start)

        return super(function, self).render_node_udraw_update()
        
    ####################################################################################################################
    # PROPERTIES
    
    num_instructions = property(getNumInstructions, setNumInstructions, deleteNumInstructions, "num_instructions")
    ea_start         = property(getEaStart, setEaStart, deleteEaStart, "ea_start")
    ea_end           = property(getEaEnd, setEaEnd, deleteEaEnd, "ea_end")
    name             = property(getName, setName, deleteName, "name")
    is_import        = property(getIsImport, setIsImport, deleteIsImport, "is_import")
    flags            = property(getFlags, setFlags, deleteFlags, "flags")
    
    # Frame info properties
    
    saved_reg_size   = property(getSavedRegSize, setSavedRegSize, deleteSavedRegSize, "saved_reg_size")
    frame_size       = property(getFrameSize, setFrameSize, deleteFrameSize, "frame_size")
    ret_size         = property(getRetSize, setRetSize, deleteRetSize, "ret_size")
    local_var_size   = property(getLocalVarSize, setLocalVarSize, deleteLocalVarSize, "local_var_size")
    arg_size         = property(getArgSize, setArgSize, deleteArgSize, "arg_size")

    num_local_vars   = property(getNumLocalVars, setNumLocalVars, deleteNumLocalVars, "num_local_vars")
    num_args         = property(getNumArgs, setNumArgs, deleteNumArgs, "num_args")