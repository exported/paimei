#
# Bak Mei - The Pai Mei Backend
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

from sql_singleton  import *

class operand(object):

    dbid            = None
    DSN             = None

    __string_rep    = None
    __cached        = None
    __position      = 0

    ####################################################################################################################
    def __init__ (self, DSN, database_id=1):
        '''
        Initializes an instance of a PaiMei operand.

        @type  DSN:         String
        @param DSN:         The database file that the operand is stored in.
        @type  database_id: Integer
        @param database_id: (Optional) The id of the operand in the database.
        '''

        self.dbid = database_id
        self.DSN = DSN

    ####################################################################################################################
    def __load_from_sql (self):
        ss = sql_singleton()

        results = ss.select_operand(self.DSN, self.dbid)

        self.__string_rep   = results["operand_text"]
        self.__position     = results["position"]


    ####################################################################################################################
    def __str__ (self):

        if not self.__cached:
            self.__load_from_sql()

        return self.__string_rep

    ####################################################################################################################
    # text accessors

    def __getText (self):
        '''
        Gets the text representation for the operand.

        @rtype:  String
        @return: The stored text representing the instruction
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__string_rep

    ####

    def __setText (self, value):
        '''
        Sets the text representation for the operand.

        @type  value: String
        @param value: The stored text representing the instruction
        '''

        if self.__cached:
            self.__string_rep = value

        ss = sql_singleton()
        ss.update_operand_text(self.DSN, self.dbid, value)

    ####

    def __deleteText (self):
        '''
        destructs the first operand of the instruction
        '''
        del self.__string_rep

    ####################################################################################################################
    # PROPERTIES
    text        = property(__getText,   __setText,  __deleteText,   "The operand text.")