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

import MySQLdb
from pysqlite2 import dbapi2 as sqlite
from sqlite_queries import *

import bakmei

class sql_singleton(object):
    '''
     A singleton used to store the SQL connection

    @author:       Cameron Hotchkies
    @license:      GNU General Public License 2.0 or later
    @contact:      chotchkies@tippingpoint.com
    @organization: www.tippingpoint.com
    '''

    # storage for the instance reference
    __instance = None

    def sql_safe_str(self, string_val):
        return "'" + string_val.replace("'", "''") + "'"

    def extract_DSN_values(DSN):
        '''
        To be honest this is not really a standard DSN format, kind of a hack that looks similar and I call it DSN

        @rtype: tuple
        @return: A tuple containing the parsed information. The structure of the tuple changes based on the source database.
        '''
        sections = DSN.split(';')

        if len(sections) == 1:
            # This case means it wasn't a DSN string, so it is probably the default sqlite pathname
            return sections
        elif sections[0] == "sqlite":
            ret_val = ()

            if sections[1][:5].upper() == "PATH=":
                sections[1] = sections[1][5:]

            ret_val.append(sections[1])

            return ret_val
        elif sections[0] == "mysql":

            server = port = dbname = uid = pwd = None

            for entry in sections[1:]:
                temp = entry.split('=')
                if temp[0].upper() == "SERVER":
                    server = temp[1]
                elif temp[0].upper() == "PORT":
                    port = temp[1]
                elif temp[0].upper() == "DATABASE":
                    dbname = temp[1]
                elif temp[0].upper() == "UID":
                    uid = temp[1]
                elif temp[0].upper() == "PWD":
                    pwd = temp[1]

            return (server, port, dbname, uid, pwd)

        return None

    class __impl(object):
        '''
        Implementation of the singleton interface
        '''

        # storage for the instance connection
        __sql               = {}
        __active_DSN = None
        __active_syntax     = "sqlite"

        def isNumber(value):
            '''
            Checks to see if a value is a number.
            '''
            try:
                # Use float, because int doesn't allow for decimals
                x = float(value)
                return True
            except ValueError:
                return False

        def test(self):
            print "inner"


        INSERT_INSTRUCTION                     = cINSERT_INSTRUCTION
        INSERT_MODULE                          = cINSERT_MODULE
        INSERT_FUNCTION                        = cINSERT_FUNCTION
        INSERT_BASIC_BLOCK                     = cINSERT_BASIC_BLOCK
        INSERT_OPERAND                         = cINSERT_OPERAND

        ## OPERAND ###

        def select_operand(self, DSN, operand_id):
            ret_val = {}

            sql_query = None

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_OPERAND
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_OPERAND

            results = curs.execute(sql_query % operand_id).fetchone()

            ret_val = {'operand_text':results[0], 'position':results[1]}

            return ret_val

        def update_operand_text(self, DSN, operand_id, text):
            if text:
                text = "'" + text.replace("'",  "''") + "'"
            else:
                text = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_OPERAND_TEXT % (text, operand_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_OPERAND_TEXT % (text, operand_id))
                curs.commit()

        ## INSTRUCTION ###

        def select_instruction(self, DSN, instruction_id):
            ret_val = {}

            sql_query = None

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_INSTRUCTION
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_INSTRUCTION

            results = curs.execute(sql_query % instruction_id).fetchone()

            ret_val = {'address':results[0], 'mnemonic':results[1], 'comment':results[5], 'bytes':results[6], 'basic_block':results[7]}

            return ret_val

        def select_instruction_operands(self, DSN, instruction_id):
            ret_val = []

            sql_query = None

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_INSTRUCTION_OPERANDS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_INSTRUCTION_OPERANDS

            results = curs.execute(sql_query % instruction_id).fetchall()

            for result in results:
                ret_val.append(result[0])

            return ret_val

        def select_instruction_references_to(self, DSN, instruction_id):
            ret_val = []

            sql_query = None

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_INSTRUCTION_XREFS_TO
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_INSTRUCTION_XREFS_TO

            results = curs.execute(sql_query % instruction_id).fetchall()

            for result in results:
                ret_val.append(result[0])

            return ret_val

        def update_instruction_mnemonic(self, DSN, instruction_id, mnemonic):
            if mnemonic:
                mnemonic = "'" + mnemonic.replace("'",  "''") + "'"
            else:
                mnemonic = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_INSTRUCTION_MNEMONIC % (mnemonic, instruction_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_INSTRUCTION_MNEMONIC % (mnemonic, instruction_id))
                curs.commit()

        def update_instruction_comment(self, DSN, instruction_id, comment):
            if comment:
                comment = "'" + comment.replace("'",  "''") + "'"
            else:
                comment = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_INSTRUCTION_COMMENT % (comment, instruction_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_INSTRUCTION_COMMENT % (comment, instruction_id))
                curs.commit()

        def update_instruction_operand(self, DSN, instruction_id, operand_seq, value):
            if value:
                value = "'" + value.replace("'",  "''") + "'"
            else:
                value = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                if operand_seq == 1:
                    sql = bakmei.mysql_queries.cUPDATE_INSTRUCTION_OPERAND1
                elif operand_seq == 2:
                    sql = bakmei.mysql_queries.cUPDATE_INSTRUCTION_OPERAND2
                elif operand_seq == 3:
                    sql = bakmei.mysql_queries.cUPDATE_INSTRUCTION_OPERAND3

                curs.execute(sql % (value, instruction_id))

            else: #sqlite
                curs = self.connection(DSN)
                if operand_seq == 1:
                    sql = bakmei.sqlite_queries.cUPDATE_INSTRUCTION_OPERAND1
                elif operand_seq == 2:
                    sql = bakmei.sqlite_queries.cUPDATE_INSTRUCTION_OPERAND2
                elif operand_seq == 3:
                    sql = bakmei.sqlite_queries.cUPDATE_INSTRUCTION_OPERAND3

                curs.execute(sql % (value, instruction_id))

                curs.commit()

        def update_instruction_flags(self, DSN, instruction_id, flags):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_INSTRUCTION_FLAGS % (flags, instruction_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_INSTRUCTION_FLAGS % (flags, instruction_id))
                curs.commit()

        def update_instruction_address(self, DSN, instruction_id, address):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_INSTRUCTION_ADDRESS % (address, instruction_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_INSTRUCTION_ADDRESS % (address, instruction_id))
                curs.commit()

        def update_instruction_bytes(self, DSN, instruction_id, byte_string):
            if byte_string:
                byte_string = "'" + byte_string.replace("'",  "''") + "'"
            else:
                byte_string = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_INSTRUCTION_BYTES % (byte_string, instruction_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_INSTRUCTION_BYTES % (byte_string, instruction_id))
                curs.commit()

        ## BASIC BLOCK ###

        def select_basic_block(self, DSN, basic_block_id):
            ret_val = {}

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                bakmei.mysql_queries.cSELECT_BASIC_BLOCK
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_BASIC_BLOCK

            results = curs.execute(sql_query % basic_block_id).fetchone()

            ret_val = {'module':results[0], 'function':results[1], 'start_address':results[2], 'end_address':results[3]}

            return ret_val

        def select_basic_block_num_instructions(self, DSN, basic_block_id):
            ret_val = 0

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_BASIC_BLOCK_NUM_INSTRUCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_BASIC_BLOCK_NUM_INSTRUCTIONS

            results = curs.execute(sql_query % basic_block_id).fetchone()
            ret_val = results[0]

            return ret_val

        def select_basic_block_sorted_instructions(self, DSN, basic_block_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_BASIC_BLOCK_SORTED_INSTRUCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_BASIC_BLOCK_SORTED_INSTRUCTIONS

            results = curs.execute(sql_query % basic_block_id).fetchall()

            for result_id in results:
                ret_val.append(result_id[0])

            return ret_val

        def update_basic_block_start_address(self, DSN, basic_block_id, address):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_BASIC_BLOCK_START_ADDRESS % (address, basic_block_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_BASIC_BLOCK_START_ADDRESS % (address, basic_block_id))
                curs.commit()

        def update_basic_block_end_address(self, DSN, basic_block_id, address):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_BASIC_BLOCK_END_ADDRESS % (address, basic_block_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_BASIC_BLOCK_END_ADDRESS % (address, basic_block_id))
                curs.commit()

        ## FUNCTION ###

        def select_function(self, DSN, function_id):
            ret_val = {}

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FUNCTION
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION

            results = curs.execute(sql_query % function_id).fetchone()

            if results[5] and results[5] != 0:
                exported = True
            else:
                exported = False

            ret_val = {'name':results[0], 'module':results[1], 'start_address':results[2], 'end_address':results[3], 'import_id':results[4], 'exported':exported}

            return ret_val

        def select_function_instruction_references_to(self, DSN, function_id):
            ret_val = []

            function_attr = self.select_function(DSN, function_id)

            is_import = True

            if function_attr["import_id"] == None or function_attr["import_id"] < 1:
                is_import = False

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                if is_import:
                    sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_DATA_REF_INSTRUCTION % function_attr["start_address"]
                else:
                    sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_CODE_REF_INSTRUCTION % function_id
            else: #sqlite
                curs = self.connection(DSN)
                if is_import:
                    sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_DATA_REF_INSTRUCTION % function_attr["start_address"]
                else:
                    sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_CODE_REF_INSTRUCTION % function_id

            results = curs.execute(sql_query).fetchall()

            for result in results:
                ret_val.append(result[0])

            return ret_val

        def select_frame_info(self, DSN, function_id):
            ret_val = {}

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FRAME_INFO
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FRAME_INFO

            results = curs.execute(sql_query % function_id).fetchone()

            ret_val = {'saved_reg_size':results[0], 'frame_size':results[1], 'ret_size':results[2], 'local_var_size': results[3], 'arg_size':results[4]}

            return ret_val

        def select_args(self, DSN, function_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_ARGS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_ARGS

            results = curs.execute(sql_query % function_id).fetchall()

            for result_row in results:
                ret_val.append({'name':result_row[0]})

            return ret_val


        def select_local_vars(self, DSN, function_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_LOCAL_VARS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_LOCAL_VARS

            results = curs.execute(sql_query % function_id).fetchall()

            for result_row in results:
                ret_val.append({'name':result_row[0]})

            return ret_val

        def select_function_basic_blocks(self, DSN, function_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_BASIC_BLOCKS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCKS

            results = curs.execute(bakmei.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCKS % function_id).fetchall()

            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_function_num_instructions(self, DSN, function_id):
            ret_val = 0

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_NUM_INSTRUCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_NUM_INSTRUCTIONS

            results = curs.execute(sql_query % function_id).fetchone()
            ret_val = results[0]

            return ret_val

        def select_function_num_vars(self, DSN, function_id, var_type):
            ret_val = 0

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_NUM_VARS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_NUM_VARS

            results = curs.execute(sql_query % (function_id, var_type)).fetchone()
            ret_val = results[0]

            return ret_val

        def select_function_basic_block_by_address(self, DSN, function_id, address):
            ret_val = None

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_BASIC_BLOCK_BY_ADDRESS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCK_BY_ADDRESS

            result = curs.execute(sql_query % (function_id, address, address)).fetchone()
            if result:
                ret_val = result[0]

            return ret_val

        def select_function_basic_block_references(self, DSN, function_id):
            '''
            Returns a list of tuples consisting of the source basic block address and the destination basic block address.
            '''
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_FUNCTION_BASIC_BLOCK_REFERENCES
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCK_REFERENCES

            results = curs.execute(sql_query % (function_id, function_id)).fetchall()
            for result_row in results:
                ret_val.append((result_row[0], result_row[1]))

            return ret_val

        def update_function_start_address(self, DSN, function_id, address):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_START_ADDRESS % (address, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_START_ADDRESS % (address, function_id))
                curs.commit()

        def update_function_end_address(self, DSN, function_id, address):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_END_ADDRESS % (address, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_END_ADDRESS % (address, function_id))
                curs.commit()

        def update_function_flags(self, DSN, function_id, flags):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_FLAGS % (flags, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_FLAGS % (flags, function_id))
                curs.commit()

        def update_function_exported(self, DSN, function_id, exported):
            if exported == True:
                export_value = 1
            else:
                export_value = 0

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_EXPORTED % (exported, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_EXPORTED % (exported, function_id))
                curs.commit()

        def update_function_arg_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_ARG_SIZE % (size, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_ARG_SIZE % (size, function_id))
                curs.commit()

        def update_function_name(self, DSN, function_id, name):
            if name:
                name = "'" + name.replace("'",  "''") + "'"
            else:
                name = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_NAME % (name, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_NAME % (name, function_id))
                curs.commit()

        def update_function_saved_reg_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_SAVED_REG_SIZE % (size, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_SAVED_REG_SIZE % (size, function_id))
                curs.commit()

        def update_function_frame_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_FRAME_SIZE % (size, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_FRAME_SIZE % (size, function_id))
                curs.commit()

        def update_function_ret_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_RET_SIZE % (size, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_RET_SIZE % (size, function_id))
                curs.commit()


        def update_function_local_var_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_FUNCTION_LOCAL_VAR_SIZE % (size, function_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_FUNCTION_LOCAL_VAR_SIZE % (size, function_id))
                curs.commit()

        def select_modules(self, DSN):
            '''
            Retrieve the name and IDs of all modules in the database.
            
            @type   DSN:        String
            @param  DSN:        The database source name.
            
            @rtype:             [(Integer, String)]
            @return:            A list of tuples containing the module ID and the module name.
            '''
            ret_val = []
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULES
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULES
        
            results = curs.execute(sql_query).fetchall()
            
            for row in results:
                ret_val.append((row[0], row[1]))
                
            return ret_val

        ## MODULE ###

        def select_module(self, DSN, module_id):
            ret_val = {}
            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE

            results = curs.execute(sql_query % module_id).fetchone()

            ret_val["name"]         = results[0]
            ret_val["base"]         = results[1]
            ret_val["signature"]    = results[2]
            ret_val["comment"]      = results[3]

            return ret_val

        def select_rpc_uuids(self, DSN, module_id):
            '''
            Retrieve all the RPC UUIDs for the given module
            '''
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_RPC_UUIDS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_RPC_UUIDS

            results = curs.execute(sql_query % module_id).fetchall()
            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_rpc_functions(self, DSN, module_id):
            '''
            Retrieve all the RPC function IDs for the given module
            '''
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_RPC_FUNCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_RPC_FUNCTIONS

            results = curs.execute(sql_query % module_id).fetchall()

            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_rpc_functions_by_uuid(self, DSN, module_id, uuid):
            '''
            Retrieve all the RPC function IDs for the given UUID in the module
            '''
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_RPC_FUNCTIONS_BY_UUID
            else: #sqlitecSELECT_RPC_FUNCTIONS_BY_UUID
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_RPC_FUNCTIONS_BY_UUID

            results = curs.execute(sql_query % (module_id, "'" + uuid.replace("'", "''") + "'")).fetchall()

            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_module_function_references(self, DSN, module_id):
            '''
            Returns a list of tuples consisting of the source function address and the destination function address.
            '''
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE_FUNCTION_REFERENCES
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE_FUNCTION_REFERENCES

            results = curs.execute(sql_query % (module_id, module_id)).fetchall()

            for result_row in results:
                ret_val.append((result_row[0], result_row[1]))

            return ret_val

        def select_module_num_functions(self, DSN, module_id):
            ret_val = 0

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE_NUM_FUNCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE_NUM_FUNCTIONS

            results = curs.execute(sql_query % module_id).fetchone()
            ret_val = results[0]

            return ret_val

        def select_module_imported_functions(self, DSN, module_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE_IMPORTED_FUNCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE_IMPORTED_FUNCTIONS

            results = curs.execute(sql_query % module_id).fetchall()

            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_module_library_functions(self, DSN, module_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE_LIBRARY_FUNCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE_LIBRARY_FUNCTIONS

            results = curs.execute(sql_query % module_id).fetchall()

            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_module_functions(self, DSN, module_id):
            ret_val = []

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE_FUNCTIONS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE_FUNCTIONS

            results = curs.execute(sql_query % module_id).fetchall()

            for result_row in results:
                ret_val.append(result_row[0])

            return ret_val

        def select_module_instruction_by_address(self, DSN, module_id, address):
            '''
            Retrieve all the instruction ID that corresponds to the address in the given module
            '''
            ret_val = None

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                sql_query = bakmei.mysql_queries.cSELECT_MODULE_INSTRUCTION_BY_ADDRESS
            else: #sqlite
                curs = self.connection(DSN)
                sql_query = bakmei.sqlite_queries.cSELECT_MODULE_INSTRUCTION_BY_ADDRESS

            results = curs.execute(sql_query % (module_id, address)).fetchone()

            # TODO : Test this logic
            if results == None or len(results) == 0:
                return None

            return results[0]

        def update_module_comment(self, DSN, module_id, comment, author):
            raise NotImplementedException
            
            # TODO: handle proper insertions
            
            if comment:
                comment = "'" + comment.replace("'",  "''") + "'"
            else:
                comment = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                
                curs.execute(bakmei.mysql_queries.cUPDATE_MODULE_COMMENT % (comment, author, module_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_MODULE_COMMENT % (comment, author, module_id))
                curs.commit()

        def update_module_name(self, DSN, module_id, name):
            if name:
                name = "'" + name.replace("'",  "''") + "'"
            else:
                name = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_MODULE_NAME % (name, module_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_MODULE_NAME % (name, module_id))
                curs.commit()

        def update_module_base(self, DSN, module_id, base):
            if not isNumber(base):
                base = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_MODULE_BASE % (base, module_id))

            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_MODULE_BASE % (base, module_id))
                curs.commit()

        def update_module_signature(self, DSN, module_id, signature):
            if signature:
                signature = "'" + signature.replace("'",  "''") + "'"
            else:
                signature = "NULL"

            if DSN[:6] == "mysql;":
                curs = self.connection(DSN).cursor()
                curs.execute(bakmei.mysql_queries.cUPDATE_MODULE_SIGNATURE % (signature, module_id))
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(bakmei.sqlite_queries.cUPDATE_MODULE_SIGNATURE % (signature, module_id))
                curs.commit()

        def connection(self, DSN=None):
            '''
            return the SQL connection object
            '''

            if DSN == None:
                DSN = self.__active_DSN

            if not self.__sql.has_key(DSN):
                # Connection missing
                try:
                    self.__init_connection(DSN)
                except sqlite.DatabaseError:
                    raise InvalidDatabaseException

            return self.__sql[DSN]

        def __init_connection(self, DSN):
            if DSN[:6] == "mysql;":
                db_values = sql_singleton.extract_DSN_values(DSN)

                try:
                    self.__sql[DSN] = MySQLdb.connect(host=db_values[0], user=db_values[3], passwd=db_values[4], db=db_values[2])
                except MySQLdb.OperationalError, err:
                    if err[0] == 1049:
                        # DB doesn't exist, let's make it!
                        create_bakmei_database(DSN)
                    else:
                        raise MySQLdb.OperationalError, err
            else:
                #sqlite
                self.__sql[DSN] = sqlite.connect(DSN)

                tables =  self.__sql[DSN].cursor().execute("SELECT name from sqlite_master where type='table';")

                if len(tables.fetchall()) == 0:
                    self.create_bakmei_database(DSN)

            self.__active_DSN = DSN  #TEMP

        def create_bakmei_database(self, DSN):
            if DSN[:6] == "mysql;":
                db_values = sql_singleton.extract_DSN_values(DSN)

                __sql[DSN] = MySQLdb.connect(host=db_values[0], user=db_values[3], passwd=db_values[4])
                cursor = self.__sql[DSN].cursor()

                # create db
                cursor.execute("CREATE DATABASE %s" % db_values[2])
                cursor.execute("USE %s" + db_values[2])

                # create tables
                for query in bakmei.mysql_queries.MYSQL_CREATE_BAKMEI_SCHEMA:
                    cursor.execute(query)
            else: #sqlite
                cursor = self.__sql[DSN].cursor()

                for query in bakmei.sqlite_queries.SQLITE_CREATE_BAKMEI_SCHEMA:
                    cursor.execute(query)

                self.__sql[DSN].commit()


        def __del__(self):
            # TODO Close all database connections
            pass

        def cursor(self):
            return self.__sql[self.__active_DSN].cursor()

############### Wrapper properties to expose methods to the documentation ####################

    def select_operand(self, DSN, operand_id):
        '''
        Retrieve the attributes of the operand.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   operand_id:     Integer
        @param  operand_id:     The ID of the operand to query.

        @rtype:                 dict
        @return:                A dict containing the operand attributes. The keys for the dictionary are "operand_text", "position".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_operand(DSN, operand_id)

    def update_operand_text(self, DSN, operand_id, text):
        '''
        Update the text of an operand in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   operand_id:     Integer
        @param  operand_id:     The ID of the operand to update.
        @type   text:           String
        @param  text:           The text of the operand.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_operand_text(DSN, operand_id, text)

    def select_instruction(self, DSN, instruction_id):
        '''
        Retrieve the attributes of the instruction.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to query.

        @rtype:                 dict
        @return:                A dict containing the instruction attributes. The keys for the dictionary are "address", "mnemonic", "comment", "bytes", "basic_block".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_instruction(DSN, instruction_id)

    def select_instruction_operands(self, DSN, instruction_id):
        '''
        Retrieve the operands of the instruction.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to query.

        @rtype:                 [Integer]
        @return:                A list containing the IDs of the operands belonging to this instruction.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_instruction_operands(DSN, instruction_id)

    def select_instruction_references_to(self, DSN, instruction_id):
        '''
        Retrieve the instructions that reference the given instruction.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to query.

        @rtype:                 [Integer]
        @return:                A list of IDs of the instructions that reference the given instruction.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_instruction_references_to(DSN, instruction_id)

    def update_instruction_mnemonic(self, DSN, instruction_id, mnemonic):
        '''
        Update the mnemonic of an instruction in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to update.
        @type   mnemonic:       String
        @param  mnemonic:       The mnemonic of the instruction.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_instruction_mnemonic(DSN, instruction_id, mnemonic)

    def update_instruction_comment(self, DSN, instruction_id, comment):
        '''
        Update the comment on an instruction in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to update.
        @type   comment:        String
        @param  comment:        The comment on the instruction.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_instruction_comment(DSN, instruction_id, comment)

    def update_instruction_operand(self, DSN, instruction_id, operand_seq, value):
        '''
        Update the operand of an instruction.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to update.
        @type   operand_seq:    Integer
        @param  operand_seq:    The placement of the operand in the instruction.
        @type   value:          String
        @param  value:          The textual representation of the operand.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_instruction_operand(DSN, instruction_id, operand_seq, value)

    def update_instruction_flags(self, DSN, instruction_id, flags):
        '''
        Update the flags of an instruction in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to update.
        @type   flags:          Integer
        @param  flags:          The flags of the instruction.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_instruction_flags(DSN, instruction_id, flags)

    def update_instruction_address(self, DSN, instruction_id, address):
        '''
        Update the address of an instruction in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to update.
        @type   address:        Integer
        @param  address:        The address of the instruction.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_instruction_address(DSN, instruction_id, address)

    def update_instruction_bytes(self, DSN, instruction_id, byte_string):
        '''
        Update the bytes of an instruction in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   instruction_id: Integer
        @param  instruction_id: The ID of the instruction to update.
        @type   byte_string:    String
        @param  byte_string:    The bytes of the instruction packed in hex.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_instruction_bytes(DSN, instruction_id, byte_string)

    ## BASIC BLOCK ###

    def select_basic_block(self, DSN, basic_block_id):
        '''
        Retrieve the attributes of the basic block.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   basic_block_id: Integer
        @param  basic_block_id: The ID of the basic_block to query.

        @rtype:                 dict
        @return:                A dictionary of all the attributes for the given basic block. The keys for the dictionary are "module", "function", "start_address", "end_address".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_basic_block(DSN, basic_block_id)

    def select_basic_block_num_instructions(self, DSN, basic_block_id):
        '''
        Retrieve the number of instructions contained in the basic block.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   basic_block_id: Integer
        @param  basic_block_id: The ID of the basic_block to query.

        @rtype:                 Integer
        @return:                The number of instructions contained in the basic block.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_basic_block_num_instructions(DSN, basic_block_id)

    def select_basic_block_sorted_instructions(self, DSN, basic_block_id):
        '''
        Retrieve the instructions contained in the basic block ordered by address.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   basic_block_id: Integer
        @param  basic_block_id: The ID of the basic_block to query.

        @rtype:                 [Integer]
        @return:                A list of the IDs of the instructions contained in the basic block.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_basic_block_sorted_instructions(DSN, basic_block_id)

    def update_basic_block_start_address(self, DSN, basic_block_id, address):
        '''
        Update the starting address of a basic block in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   basic_block_id: Integer
        @param  basic_block_id: The ID of the basic block to update.
        @type   address:        Integer
        @param  address:        The basic block starting address.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_basic_block_start_address(DSN, basic_block_id, address)

    def update_basic_block_end_address(self, DSN, basic_block_id, address):
        '''
        Update the ending address of a basic block in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   basic_block_id: Integer
        @param  basic_block_id: The ID of the basic block to update.
        @type   address:        Integer
        @param  address:        The basic block ending address.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_basic_block_end_address(DSN, basic_block_id, address)

    ## FUNCTION ###

    def select_function(self, DSN, function_id):
        '''
        Retrieve the attributes of the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 dict
        @return:                A dict containing the function attributes. The keys for the dictionary are "name", "module", "start_address", "end_address", "import_id", "exported".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function(DSN, function_id)

    def select_function_instruction_references_to(self, DSN, function_id):
        '''
        Retrieve a list of instructions that reference the given function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 [integer]
        @return:                A list of the IDs of the instructions that reference the given function.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function_instruction_references_to(DSN, function_id)

    def select_frame_info(self, DSN, function_id):
        '''
        Retrieve the frame information for the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 dict
        @return:                A dict containing the frame information attributes. The keys for the dictionary are "saved_reg_size", "frame_size", "ret_size", "local_var_size", "arg_size".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_frame_info(DSN, function_id)

    def select_args(self, DSN, function_id):
        '''
        Retrieve the arguments of the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 [dict]
        @return:                A list of dicts containing the argument attributes. The keys for the dictionary are "name".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_args(DSN, function_id)

    def select_local_vars(self, DSN, function_id):
        '''
        Retrieve the local variables of the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 [dict]
        @return:                A list of dicts containing the local variable attributes. The keys for the dictionary are "name".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_local_vars(DSN, function_id)

    def select_function_basic_blocks(self, DSN, function_id):
        '''
        Retrieve the basic blocks contained in the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 [Integer]
        @return:                A list of the IDs of the basic blocks contained in the function.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function_basic_blocks(DSN, function_id)

    def select_function_num_instructions(self, DSN, function_id):
        '''
        Retrieve the number of instructions contained in the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.

        @rtype:                 Integer
        @return:                The number of instructions contained in the function.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function_num_instructions(DSN, function_id)

    def select_function_num_vars(self, DSN, function_id, var_type):
        '''
        Retrieve the number of a given type of variables in the function.

        VAR_TYPE_ARGUMENT   = 1

        VAR_TYPE_LOCAL      = 2

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.
        @type   var_type:       Integer
        @param  var_type:       The address contained in the basic block.
        @rtype:                 Integer
        @return:                The number of variables in the function.

        @seealso:               defines.py
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function_num_vars(DSN, function_id, var_type)

    def select_function_basic_block_by_address(self, DSN, function_id, address):
        '''
        Retrieve the basic block in the function containing the given address.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.
        @type   address:        Integer
        @param  address:        The address contained in the basic block.
        @rtype:                 Integer
        @return:                The ID of the basic block to be retrieved.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function_basic_block_by_address(DSN, function_id, address)

    def select_function_basic_block_references(self, DSN, function_id):
        '''
        Retrieve the basic block cross references for the function.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to query.
        @rtype:                 tuple
        @return:                A tuple in the format of (src_basic_block_id, dst_basic_block_id).
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_function_basic_block_references(DSN, function_id)

    def update_function_start_address(self, DSN, function_id, address):
        '''
        Update the starting address of a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   address:        Integer
        @param  address:        The function starting address.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_start_address(DSN, function_id, address)

    def update_function_end_address(self, DSN, function_id, address):
        '''
        Update the ending address of a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   address:        Integer
        @param  address:        The function end address.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_end_address(DSN, function_id, address)

    def update_function_exported(self, DSN, function_id, exported):
        '''
        Update the flags for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   exported:       Boolean
        @param  exported:       The function export status.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_exported(DSN, function_id, exported)

    def update_function_flags(self, DSN, function_id, flags):
        '''
        Update the flags for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   flags:          Integer
        @param  flags:          The function flags.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_flags(DSN, function_id, flags)

    def update_function_arg_size(self, DSN, function_id, size):
        '''
        Update the function argument size for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   size:           Integer
        @param  size:           The total function arguments size.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_arg_size(DSN, function_id, size)

    def update_function_name(self, DSN, function_id, name):
        '''
        Update the name of a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   name:           String
        @param  name:           The name of the function.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_name(DSN, function_id, name)

    def update_function_saved_reg_size(self, DSN, function_id, size):
        '''
        Update the saved registers size for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   size:           Integer
        @param  size:           The saved registers size.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_saved_reg_size(DSN, function_id, size)

    def update_function_frame_size(self, DSN, function_id, size):
        '''
        Update the frame size for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   size:           Integer
        @param  size:           The frame size.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_frame_size(DSN, function_id, size)

    def update_function_ret_size(self, DSN, function_id, size):
        '''
        Update the return variable size for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   size:           Integer
        @param  size:           The return variable size.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_ret_size(DSN, function_id, size)

    def update_function_local_var_size(self, DSN, function_id, size):
        '''
        Update the local variable size for a function in the database.

        @type   DSN:            String
        @param  DSN:            The database source name.
        @type   function_id:    Integer
        @param  function_id:    The ID of the function to update.
        @type   size:           Integer
        @param  size:           The local variable size.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_function_local_var_size(DSN, function_id, size)

    def select_modules(self, DSN):
        '''
        Retrieve the name and IDs of all modules in the database.
        
        @type   DSN:        String
        @param  DSN:        The database source name.
        
        @rtype:             [(Integer, String)]
        @return:            A list of tuples containing the module ID and the module name.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_modules(DSN)
        
    ## MODULE ###

    def select_module(self, DSN, module_id):
        '''
        Retrieve all the attributes of the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to retrieve.

        @rtype:             dict
        @return:            A dictionary of all the attributes for the given module. The keys for the dictionary are "name", "base", "signature", "comment".
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module(DSN, module_id)

    def select_rpc_uuids(self, DSN, module_id):
        '''
        Retrieve all the RPC UUIDs for the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to search.

        @rtype:             List
        @return:            A list of all the RPC UUIDs available for the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_rpc_uuids(DSN, module_id)

    def select_rpc_functions(self, DSN, module_id):
        '''
        Retrieve all the RPC function IDs for the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to search.

        @rtype:             List
        @return:            A list of all the RPC function IDs available for the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_rpc_functions(DSN, module_id)

    def select_rpc_functions_by_uuid(self, DSN, module_id, uuid):
        '''
        Retrieve all the RPC function IDs for the given UUID in the module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to search.
        @type   uuid:       String
        @param  uuid:       The uuid to search for matching functions.

        @rtype:             List
        @return:            A list of all the RPC function IDs available for the UUID in the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_rpc_functions_by_uuid(DSN, module_id)

    def select_module_function_references(self, DSN, module_id):
        '''
        Returns a list of tuples consisting of the source function address and the destination function address.

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to query.

        @rtype:             (Integer, Integer)
        @return:            A tuple in the format of (src_function_id, dst_function_id).
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module_function_references(DSN, module_id)

    def select_module_num_functions(self, DSN, module_id):
        '''
        Retrieve the number of functions contained in the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to query.

        @rtype:             Integer
        @return:            The number of functions contained in the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module_num_functions(DSN, module_id)

    def select_module_imported_functions(self, DSN, module_id):
        '''
        Retrieve all the function IDs that are imported into the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to query.

        @rtype:             [Integer]
        @return:            A list of the imported function IDs contained in the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module_imported_functions(DSN, module_id)

    def select_module_library_functions(self, DSN, module_id):
        '''
        Retrieve all the function IDs that are inline library calls for the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to query.

        @rtype:             [Integer]
        @return:            A list of the inline library function IDs contained in the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module_library_functions(DSN, module_id)

    def select_module_instruction_by_address(self, DSN, module_id, address):
        '''
        Retrieve all the instruction ID that corresponds to the address in the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to query.
        @type   address:    DWORD
        @param  address:    The address of the instruction.

        @rtype:             Integer
        @return:            The instruction ID matching the address contained in the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module_instruction_by_address(DSN, module_id, address)

    def select_module_functions(self, DSN, module_id):
        '''
        Retrieve all the function IDs that are contained in the given module

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to query.

        @rtype:             [Integer]
        @return:            A list of the function IDs contained in the module.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.select_module_functions(DSN, module_id)

    def update_module_name(self, DSN, module_id, name):
        '''
        Update the module name in the database.

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to update.
        @type   name:       String
        @param  name:       The module name to store in the database.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_module_name(DSN, module_id, name)
        
    def update_module_comment(self, DSN, module_id, comment, author):
        '''
        Update the module comment in the database.

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to update.
        @type   name:       String
        @param  name:       The module comment to store in the database.
        @type   author:     String
        @param  author:     The name of the person adding the comment.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_module_comment(DSN, module_id, comment, author)        

    def update_module_base(self, DSN, module_id, base):
        '''
        Update the module base address in the database.

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to update.
        @type   base:       Integer
        @param  base:       The base address to store in the database.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_module_base(DSN, module_id, base)

    def update_module_signature(self, DSN, module_id, signature):
        '''
        Update the module signature in the database.

        @type   DSN:        String
        @param  DSN:        The database source name.
        @type   module_id:  Integer
        @param  module_id:  The ID of the module to update.
        @type   signature:  String
        @param  signature:  The signature to store in the database.
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.update_module_signature(DSN)

    def connection(self, DSN):
        '''
        Get the SQL connection object.
        This method is used to create the initial connection, and should not be called afterwards.
        This should not be used when you can use the execute method.

        @return: the SQL connection object

        @seealso: sql_singleton.execute()
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.connection(DSN)

    def create_bakmei_database(self, DSN):
        '''
        Creates the schema for a Bak Mei database at the given DSN.

        @type   DSN: String
        @param  DSN: The database source name
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.create_bakmei_database(DSN)

    def cursor(self):
        '''
        Get the SQL cursor object for the current connection. This should not be used when you can use the execute method.

        @return:    the SQL cursor object
        @rtype:     cursor

        @seealso:   sql_singleton.execute()
        '''
        if sql_singleton.__instance is None:
            raise SingletonInstanceException

        return sql_singleton.__instance.cursor()


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

    def test(self):
        print sql_singleton.__instance
        print "outer"

class SingletonInstanceException(Exception):
    def __str__(self):
        return "The sql_singleton class must be instantiated before this method can be called."
        
class InvalidDatabaseException(Exception):
    def __str__(self):
        return "Invalid database path."