#
# PIDA SQL Singleton
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

import MySQLdb
from pysqlite2 import dbapi2 as sqlite
from sqlite_queries import *

class sql_singleton:
    '''
     A singleton used to store the SQL connection
   
    @author:       Cameron Hotchkies
    @license:      GNU General Public License 2.0 or later
    @contact:      chotchkies@tippingpoint.com
    @organization: www.tippingpoint.com
    '''

    # storage for the instance reference
    __instance = None

    class __impl:
        '''
        Implementation of the singleton interface
        '''

        # storage for the instance connection
        __sql               = {}
        __active_DSN = None
        __active_syntax     = "sqlite"

        INSERT_INSTRUCTION                     = cINSERT_INSTRUCTION
        INSERT_MODULE                          = cINSERT_MODULE
        INSERT_FUNCTION                        = cINSERT_FUNCTION
        INSERT_BASIC_BLOCK                     = cINSERT_BASIC_BLOCK

        ## INSTRUCTION ###

        SELECT_INSTRUCTION                     = cSELECT_INSTRUCTION

        UPDATE_INSTRUCTION_MNEMONIC            = cUPDATE_INSTRUCTION_MNEMONIC
        UPDATE_INSTRUCTION_COMMENT             = cUPDATE_INSTRUCTION_COMMENT
        UPDATE_INSTRUCTION_OPERAND1            = cUPDATE_INSTRUCTION_OPERAND1
        UPDATE_INSTRUCTION_OPERAND2            = cUPDATE_INSTRUCTION_OPERAND2
        UPDATE_INSTRUCTION_OPERAND3            = cUPDATE_INSTRUCTION_OPERAND3
        UPDATE_INSTRUCTION_FLAGS               = cUPDATE_INSTRUCTION_FLAGS
        UPDATE_INSTRUCTION_ADDRESS             = cUPDATE_INSTRUCTION_ADDRESS
        UPDATE_INSTRUCTION_COMMENT             = cUPDATE_INSTRUCTION_COMMENT
        UPDATE_INSTRUCTION_BYTES               = cUPDATE_INSTRUCTION_BYTES

        ## BASIC BLOCK ###

        SELECT_BASIC_BLOCK                     = cSELECT_BASIC_BLOCK
        SELECT_NUM_INSTRUCTIONS                = cSELECT_NUM_INSTRUCTIONS
        SELECT_SORTED_INSTRUCTIONS             = cSELECT_SORTED_INSTRUCTIONS

        UPDATE_START_ADDRESS                   = cUPDATE_START_ADDRESS
        UPDATE_END_ADDRESS                     = cUPDATE_END_ADDRESS

        ## FUNCTION ###

        SELECT_FUNCTION                        = cSELECT_FUNCTION
        SELECT_FRAME_INFO                      = cSELECT_FRAME_INFO
        SELECT_ARGS                            = cSELECT_ARGS
        SELECT_LOCAL_VARS                      = cSELECT_LOCAL_VARS
        SELECT_FUNCTION_BASIC_BLOCKS           = cSELECT_FUNCTION_BASIC_BLOCKS
        SELECT_FUNCTION_NUM_INSTRUCTIONS       = cSELECT_FUNCTION_NUM_INSTRUCTIONS
        SELECT_FUNCTION_NUM_VARS               = cSELECT_FUNCTION_NUM_VARS
        SELECT_FUNCTION_BASIC_BLOCK_BY_ADDRESS = cSELECT_FUNCTION_BASIC_BLOCK_BY_ADDRESS

        SELECT_FUNCTION_BASIC_BLOCK_REFERENCES = cSELECT_FUNCTION_BASIC_BLOCK_REFERENCES
        SELECT_MODULE_FUNCTION_REFERENCES      = cSELECT_MODULE_FUNCTION_REFERENCES

        UPDATE_FUNCTION_START_ADDRESS          = cUPDATE_FUNCTION_START_ADDRESS
        UPDATE_FUNCTION_END_ADDRESS            = cUPDATE_FUNCTION_END_ADDRESS
        UPDATE_FUNCTION_FLAGS                  = cUPDATE_FUNCTION_FLAGS
        UPDATE_FUNCTION_ARG_SIZE               = cUPDATE_FUNCTION_ARG_SIZE
        UPDATE_FUNCTION_NAME                   = cUPDATE_FUNCTION_NAME
        UPDATE_FUNCTION_SAVED_REG_SIZE         = cUPDATE_FUNCTION_SAVED_REG_SIZE
        UPDATE_FUNCTION_FRAME_SIZE             = cUPDATE_FUNCTION_FRAME_SIZE
        UPDATE_FUNCTION_RET_SIZE               = cUPDATE_FUNCTION_RET_SIZE
        UPDATE_FUNCTION_LOCAL_VAR_SIZE         = cUPDATE_FUNCTION_LOCAL_VAR_SIZE

        ## MODULE ###

        SELECT_MODULE_NUM_FUNCTIONS            = cSELECT_MODULE_NUM_FUNCTIONS
        SELECT_MODULE_FUNCTIONS                = cSELECT_MODULE_FUNCTIONS

        UPDATE_MODULE_NAME                     = cUPDATE_MODULE_NAME
        UPDATE_MODULE_BASE                     = cUPDATE_MODULE_BASE
        UPDATE_MODULE_SIGNATURE                = cUPDATE_MODULE_SIGNATURE


        def connection(self, DSN=None):
            '''
            return the SQL connection object
            '''

            if DSN == None:
                DSN = self.__active_DSN

            if not self.__sql.has_key(DSN):
                self.__init_connection(DSN)

            return self.__sql[DSN]

        def __init_connection(self, DSN_name):

            if self.__active_syntax == "mysql":
                try:
                    self.__sql[DSN_name] = MySQLdb.connect(host=host, user=username, passwd=password, db="pida_" + DSN_name)
                except MySQLdb.OperationalError, err:
                    if err[0] == 1049:
                        # DB doesn't exist, let's make it!
                        create_pida_database(DSN_name)
                    else:
                        raise MySQLdb.OperationalError, err
            else:
                #sqlite
                self.__sql[DSN_name] = sqlite.connect(DSN_name)

                tables =  self.__sql[DSN_name].cursor().execute("SELECT name from sqlite_master where type='table';")

                if len(tables.fetchall()) == 0:
                    self.create_pida_database(DSN_name)


            self.__active_DSN = DSN_name  #TEMP

        def create_pida_database(self, DSN):
            #self.__sql[DSN] = MySQLdb.connect(host=host, user=username, passwd=password)
            #cursor = self.__sql[DSN].cursor()
            #
            ## create db
            #cursor.execute("CREATE DATABASE pida_" + DSN)
            #cursor.execute("USE pida_" + DSN)
            #
            ## create tables
            #for query in MYSQL_CREATE_PIDA_SCHEMA:
            #    cursor.execute(query)
            cursor = self.__sql[DSN].cursor()

            for query in SQLITE_CREATE_PIDA_SCHEMA:
                cursor.execute(query)

            self.__sql[DSN].commit()



        def cursor(self):
            return self.__sql[self.__active_DSN].cursor()

############### DO NOT MODIFY PAST THIS POINT ###############

    def __init__(self):
        '''
        Create singleton instance
        '''
        # Check whether we already have an instance
        if sql_singleton.__instance is None:
            # Create and remember instance
            sql_singleton.__instance = sql_singleton.__impl()

        # Store instance reference as the only member in the handle
        self.__dict__['_sql_singleton__instance'] = sql_singleton.__instance

    def __getattr__(self, attr):
        '''
        Delegate access to implementation
        '''
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        '''
        Delegate access to implementation
        '''
        return setattr(self.__instance, attr, value)
