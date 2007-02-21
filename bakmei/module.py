#
# Bak Mei - The Pai Mei Backend
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
# Copyright (C) 2007 Cameron Hotchkies <chotchkies@tippingpoint.com>
#
# $Id$
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

import sys
import pgraph

from sql_singleton import *

from function import *
from defines  import *


class module (pgraph.graph):
    '''
    A module is an overall container for all the information stored in a binary, whether it is an executable or a library.

    @author:       Cameron Hotchkies, Pedram Amini
    @license:      GNU General Public License 2.0 or later
    @contact:      chotchkies@tippingpoint.com
    @organization: www.openrce.org

    @cvar dbid:    Database Identifier
    @type dbid:    Integer
    @cvar DSN:     Database location
    @type DSN:     String
    '''

    # most of these should be read via properties
    __name          = None
    __base          = None
    __signature     = None

    __nodes         = None


    dbid            = None
    DSN             = None

    __cached        = False
    ext             = {}
    ####################################################################################################################
    def __init__ (self, DSN, database_id=1):
        '''
        Initializes an instance of a PaiMei module.

        @type  DSN:         String
        @param DSN:         The database file that the module is stored in.
        @type  database_id: Integer
        @param database_id: (Optional) The id of the module in the database.
        '''

        # TODO : see if these two lines are actually required, I think they were only necessary before the DSN was required
        ss = sql_singleton()
        ss.connection(DSN)

        super(module, self).__init__()

        self.dbid = database_id
        self.DSN = DSN

        # edges have to be built upfront because the superclass relies on them
        self.__build_edges()


    ####################################################################################################################
    def __build_edges(self):

        ss = sql_singleton()
        results = ss.select_module_function_references(self.DSN, self.dbid)

        for ed in results:
            newedge = edge.edge(ed[0], ed[1])

            self.add_edge(newedge)

    #################################################################################################################

    def __load_from_sql(self):
        '''
	    Loads the information about a module from a SQL datastore.
	    '''
        ss = sql_singleton()
        results = ss.select_module(self.DSN, self.dbid)

        self.__name         = results["name"]
        self.__base         = results["base"]
        self.__signature    = results["signature"]

        self.__cached = True

    ####################################################################################################################
    # name accessors

    def __getName (self):
        '''
        The name of the module.

        @rtype:  String
        @return: The name of the module
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__name

    ####

    def __setName (self, value):
        '''
        Sets the name of the module.

        @type  value: String
        @param value: The name of the module.
        '''

        if self.__cached:
            self.__name = value

        ss = sql_singleton()
        ss.update_module_name(self.DSN, self.dbid, value)

    ####

    def __deleteName (self):
        '''
        destructs the name of the module
        '''
        del self.__name

    ####################################################################################################################
    # base accessors

    def __getBase (self):
        '''
        Gets the base address of the module

        @rtype:  Dword
        @return: The base address of the module
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__base

    def __setBase (self, value):
        '''
        Sets the base address of the module.

        @type  value: Dword
        @param value: The base address of the module.
        '''

        if self.__cached:
            self.__base = value

        ss = sql_singleton()
        ss.update_module_base(self.DSN, self.dbid, value)

    def __deleteBase (self):
        '''
        destructs the base address of the module
        '''
        del self.__base

    ####################################################################################################################
    # signature accessors

    def __getSignature (self):
        '''
        Gets the signature of the module

        @rtype:  String
        @return: The signature of the module
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__signature

    def __setSignature (self, value):
        '''
        Sets the signature of the module.

        @type  value: String
        @param value: The signature of the module.
        '''

        if self.__cached:
            self.__signature = value

        ss = sql_singleton()
        ss.update_module_signature(self.DSN, self.dbid, value)

    def __deleteSignature (self):
        '''
        destructs the signature of the module
        '''
        del self.__signature

    ####################################################################################################################
    # num_functions

    def __getNumFunctions (self):
        '''
        The number of functions in the module

        @rtype:  Integer
        @return: The number of instructions in the function
        '''

        ss = sql_singleton()
        ret_val = ss.select_module_num_functions(self.DSN, self.dbid)

        return ret_val

    ####

    def __setNumFunctions (self, value):
        '''
        Sets the number of functions (raises an exception - READ ONLY)

        @type  value: Integer
        @param value: The number of functions in the module
        '''
        raise NotImplementedError, "num_functions is a read-only property"

    ####

    def __deleteNumFunctions (self):
        '''
        destructs the num_functions
        '''
        pass # dynamically generated property value

    ####################################################################################################################
    # nodes accessors

    def __getNodes (self):
        '''
        Gets the functions (nodes) of the module

        @rtype:  String
        @return: A dictionary of all the functions keyed by start addresses
        '''

        if self.__nodes == None:
            ret_val = {}
            ss = sql_singleton()
            results = ss.select_module_functions(self.DSN, self.dbid)

            for function_id in results:
                new_function = function(self.DSN, function_id)
                ret_val[new_function.ea_start] = new_function

            self.__nodes = ret_val

        return self.__nodes

    def __setNodes (self, value):
        '''
        Sets the nodes of the module. This will generate an error.

        @type  value: String
        @param value: The signature of the module.
        '''

        raise NotImplementedError, "nodes and functions are not directly writable for modules. This is a read-only property"

    def __deleteNodes (self):
        '''
        destructs the nodes of the module
        '''
        del self.__nodes

    ####################################################################################################################
    # imported_functions accessors

    def __getImportedFunctions (self):
        '''
        Gets the imported functions for the module

        @rtype:  [function]
        @return: The imported functions of the module
        '''

        ret_val = []
        ss = sql_singleton()
        results = ss.select_module_imported_functions(self.DSN, self.dbid)

        for function_id in results:
            new_function = function(self.DSN, function_id)
            ret_val.append(new_function)

        return ret_val

    def __setImportedFunctions (self, value):
        '''
        Sets the imported functions of the module. This will generate an error.

        @type  value: String
        @param value: The signature of the module.
        '''

        raise NotImplementedError, "nodes and functions are not directly writable for modules. This is a read-only property"

    def __deleteImportedFunctions (self):
        '''
        destructs the imports
        '''
        pass # dynamically generated property

    ####################################################################################################################
    # library_functions accessors

    def __getLibraryFunctions (self):
        '''
        Gets the library functions for the module

        @rtype:  [function]
        @return: The inline library functions of the module
        '''

        ret_val = []
        ss = sql_singleton()
        results = ss.select_module_library_functions(self.DSN, self.dbid)

        for function_id in results:
            new_function = function(self.DSN, function_id)
            ret_val.append(new_function)

        return ret_val

    def __setLibraryFunctions (self, value):
        '''
        Sets the imported functions of the module. This will generate an error.

        @type  value: String
        @param value: The signature of the module.
        '''

        raise NotImplementedError, "nodes and functions are not directly writable for modules. This is a read-only property"

    def __deleteLibraryFunctions (self):
        '''
        destructs the imports
        '''
        pass # dynamically generated property

    ####################################################################################################################
    def find_function (self, ea):
        '''
        Locate and return the function that contains the specified address.

        @type  ea: DWORD
        @param ea: An address within the function to find

        @rtype:  bakmei.function
        @return: The function that contains the given address or None if not found.
        '''

        for func in self.nodes.values():
            # this check is necessary when analysis_depth == DEPTH_FUNCTIONS
            if func.ea_start == ea:
                return func

            for bb in func.nodes.values():
                if bb.ea_start <= ea <= bb.ea_end:
                    return func

        return None


    ####################################################################################################################
    def next_ea (self, ea=None):
        '''
        Return the instruction after to the one at ea. You can call this routine without an argument after the first
        call. The overall structure of BAKMEI was not really designed for this kind of functionality, so this is kind of
        a hack.

        @todo: See if I can do this better.

        @type  ea: (Optional, def=Last EA) Dword
        @param ea: Address of instruction to return next instruction from or -1 if not found.
        '''

        # TODO : update this to utilize db back-end

        if not ea and self.current_ea:
            ea = self.current_ea

        function = self.find_function(ea)

        if not function:
            return -1

        ea_list = []

        for bb in function.nodes.values():
            ea_list.extend(bb.instructions.keys())

        ea_list.sort()

        try:
            idx = ea_list.index(ea)

            if idx == len(ea_list) - 1:
                raise Exception
        except:
            return -1

        self.current_ea = ea_list[idx + 1]
        return self.current_ea


    ####################################################################################################################
    def prev_ea (self, ea=None):
        '''
        Within the function that contains ea, return the instruction prior to the one at ea. You can call this routine
        without an argument after the first call. The overall structure of BAKMEI was not really designed for this kind of
        functionality, so this is kind of a hack.

        @todo: See if I can do this better.

        @type  ea: (Optional, def=Last EA) Dword
        @param ea: Address of instruction to return previous instruction to or None if not found.
        '''

        # TODO : update this to utilize database back end.

        if not ea and self.current_ea:
            ea = self.current_ea

        function = self.find_function(ea)

        if not function:
            return -1

        ea_list = []

        for bb in function.nodes.values():
            ea_list.extend(bb.instructions.keys())

        ea_list.sort()

        try:
            idx = ea_list.index(ea)

            if idx == 0:
                raise Exception
        except:
            return -1

        self.current_ea = ea_list[idx - 1]
        return self.current_ea


    ####################################################################################################################
    def rebase (self, new_base):
        '''
        Rebase the module and all components with the new base address. This routine will check if the current and
        requested base addresses are equivalent, so you do not have to worry about checking that yourself.

        @type  new_base: Dword
        @param new_base: Address to rebase module to
        '''

        # nothing to do.
        if new_base == self.base:
            return

        # TODO: rewrite for SQL backing

        # rebase each function in the module.
        for function in self.nodes.keys():
            self.nodes[function].id       = self.nodes[function].id       - self.base + new_base
            self.nodes[function].ea_start = self.nodes[function].ea_start - self.base + new_base
            self.nodes[function].ea_end   = self.nodes[function].ea_end   - self.base + new_base

            function = self.nodes[function]

            # rebase each basic block in the function.
            for bb in function.nodes.keys():
                function.nodes[bb].id       = function.nodes[bb].id       - self.base + new_base
                function.nodes[bb].ea_start = function.nodes[bb].ea_start - self.base + new_base
                function.nodes[bb].ea_end   = function.nodes[bb].ea_end   - self.base + new_base

                bb = function.nodes[bb]

                # rebase each instruction in the basic block.
                for ins in bb.instructions.keys():
                    bb.instructions[ins].ea = bb.instructions[ins].ea - self.base + new_base

                # fixup the instructions dictionary.
                old_dictionary  = bb.instructions
                bb.instructions = {}

                for key, val in old_dictionary.items():
                    bb.instructions[key - self.base + new_base] = val

            # fixup the functions dictionary.
            old_dictionary = function.nodes
            function.nodes = {}

            for key, val in old_dictionary.items():
                function.nodes[val.id] = val

            # rebase each edge between the basic blocks in the function.
            for edge in function.edges.keys():
                function.edges[edge].src =  function.edges[edge].src - self.base + new_base
                function.edges[edge].dst =  function.edges[edge].dst - self.base + new_base
                function.edges[edge].id  = (function.edges[edge].src << 32) + function.edges[edge].dst

            # fixup the edges dictionary.
            old_dictionary = function.edges
            function.edges = {}

            for key, val in old_dictionary.items():
                function.edges[val.id] = val

        # fixup the modules dictionary.
        old_dictionary = self.nodes
        self.nodes     = {}

        for key, val in old_dictionary.items():
            self.nodes[val.id] = val

        # rebase each edge between the functions in the module.
        for edge in self.edges.keys():
            self.edges[edge].src =  self.edges[edge].src - self.base + new_base
            self.edges[edge].dst =  self.edges[edge].dst - self.base + new_base
            self.edges[edge].id  = (self.edges[edge].src << 32) + self.edges[edge].dst

        # finally update the base address of the module.
        self.base = new_base


    ####################################################################################################################
    def uuid_bin_to_string (self, uuid):
        '''
        Convert the binary representation of a UUID to a human readable string.

        @type  uuid: Raw
        @param uuid: Raw binary bytes consisting of the UUID

        @rtype:  String
        @return: Human readable string representation of UUID.
        '''

        import struct

        (block1, block2, block3) = struct.unpack("<LHH", uuid[:8])
        (block4, block5, block6) = struct.unpack(">HHL", uuid[8:16])

        return "%08x-%04x-%04x-%04x-%04x%08x" % (block1, block2, block3, block4, block5, block6)

    ####################################################################################################################
    # PROPERTIES

    name                = property(__getName,               __setName,              __deleteName,               "The name of the module.")
    base                = property(__getBase,               __setBase,              __deleteBase,               "The base address of the module.")
    signature           = property(__getSignature,          __setSignature,         __deleteSignature,          "The module signature.")
    nodes               = property(__getNodes,              __setNodes,             __deleteNodes,              "The functions in the module, keyed by the starting address.")
    num_functions       = property(__getNumFunctions,       __setNumFunctions,      __deleteNumFunctions,       "The number of functions in the module.")
    imported_functions  = property(__getImportedFunctions,  __setImportedFunctions, __deleteImportedFunctions,  "The functions imported from other libraries.")
    library_functions   = property(__getLibraryFunctions,   __setLibraryFunctions,  __deleteLibraryFunctions,   "The library functions compiled inline.")