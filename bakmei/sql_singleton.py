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
import pida

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


        INSERT_INSTRUCTION                     = cINSERT_INSTRUCTION
        INSERT_MODULE                          = cINSERT_MODULE
        INSERT_FUNCTION                        = cINSERT_FUNCTION
        INSERT_BASIC_BLOCK                     = cINSERT_BASIC_BLOCK

        ## INSTRUCTION ###

        def select_instruction(self, DSN, instruction_id):
            ret_val = {}
        
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_BASIC_BLOCK % basic_block_id).fetchone()
                ret_val = {'address':results[0], 'mnemonic':results[1], 'operand1':results[2], 'operand2':results[3], 'operand3':results[4], 'comment'results[5], 'bytes':results[6], 'basic_block':results[7]}
                                
            return ret_val  

        def update_instruction_mnemonic(self, DSN, instruction_id, mnemonic):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                
                if value:
                    mnemonic = "'" + mnemonic.replace("'",  "''") + "'"
                else:
                    mnemonic = "NULL"
                
                curs.execute(pida.sqlite_queries.cUPDATE_INSTRUCTION_MNEMONIC % (mnemonic, basic_block_id))
                
                curs.commit()
        
        def update_instruction_comment(self, DSN, instruction_id, comment):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                
                if value:
                    comment = "'" + comment.replace("'",  "''") + "'"
                else:
                    comment = "NULL"
                
                curs.execute(pida.sqlite_queries.cUPDATE_INSTRUCTION_COMMENT % (comment, basic_block_id))
                
                curs.commit()
                
        
        def update_instruction_operand(self, DSN, instruction_id, operand_seq, value):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                
                if value:
                    value = "'" + value.replace("'",  "''") + "'"
                else:
                    value = "NULL"
                if operand_seq == 1:
                    sql = pida.sqlite_queries.cUPDATE_INSTRUCTION_OPERAND1
                elif operand_seq == 2:
                    sql = pida.sqlite_queries.cUPDATE_INSTRUCTION_OPERAND2
                elif operand_seq == 3:
                    sql = pida.sqlite_queries.cUPDATE_INSTRUCTION_OPERAND3
                    
                curs.execute(sql % (value, instruction_id))
                
                curs.commit()                
        
        def update_instruction_flags(self, DSN, instruction_id, flags):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_INSTRUCTION_FLAGS % (flags, instruction_id))
                curs.commit()             
        
        def update_instruction_address(self, DSN, instruction_id, address):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_INSTRUCTION_ADDRESS % (address, instruction_id))
                curs.commit()             
        
        def update_instruction_comment(self, DSN, instruction_id, comment):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                
                if value:
                    comment = "'" + comment.replace("'",  "''") + "'"
                else:
                    comment = "NULL"
                
                curs.execute(pida.sqlite_queries.cUPDATE_INSTRUCTION_COMMENT % (comment, basic_block_id))
                
                curs.commit() 
                
        def update_instruction_bytes(self, DSN, instruction_id, byte_string):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                
                if value:
                    byte_string = "'" + byte_string.replace("'",  "''") + "'"
                else:
                    byte_string = "NULL"
                
                curs.execute(pida.sqlite_queries.cUPDATE_INSTRUCTION_BYTES % (byte_string, basic_block_id))
                
                curs.commit() 

        ## BASIC BLOCK ###

        def select_basic_block(self, DSN, basic_block_id):
            ret_val = {}
        
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_BASIC_BLOCK % basic_block_id).fetchone()
                ret_val = {'module':results[0], 'function':results[1], 'start_address':results[2], 'end_address':results[3]}
                                
            return ret_val    
        
        def select_basic_block_num_instructions(self, DSN, basic_block_id):
            ret_val = 0
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_BASIC_BLOCK_NUM_INSTRUCTIONS % basic_block_id).fetchone()
                ret_val = results[0]

            return ret_val        
        
        def select_basic_block_sorted_instructions(self, DSN, basic_block_id):
            ret_val = []
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_BASIC_BLOCK_SORTED_INSTRUCTIONS % basic_block_id).fetchall()

                for result_id in results:
                    ret_val += result_id

            return ret_val             

        def update_basic_block_start_address(self, DSN, basic_block_id, address):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_BASIC_BLOCK_START_ADDRESS % (address, basic_block_id))
                curs.commit()  

        def update_basic_block_end_address(self, DSN, basic_block_id, address):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_BASIC_BLOCK_END_ADDRESS % (address, basic_block_id))
                curs.commit()  

        ## FUNCTION ###

        def select_function(self, DSN, function_id):
            ret_val = {}
        
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_FUNCTION % function_id).fetchone()
                ret_val = {'name':results[0], 'module':results[1], 'start_address':results[2], 'end_address':results[3]}
                                
            return ret_val    
            
        def select_frame_info(self, DSN, function_id):
            ret_val = {}
        
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_FRAME_INFO % function_id).fetchone()
                
                ret_val = {'saved_reg_size':results[0], 'frame_size':results[1], 'ret_size':results[2], 'local_var_size': results[3], 'arg_size':results[4]}
                                
            return ret_val             
        
        def select_args(self, DSN, function_id):
            ret_val = []

            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_ARGS % function_id).fetchall()
                
                for result_row in results:
                    ret_val += {'name':result_row[0]}

            return ret_val             
        
        
        def select_local_vars(self, DSN, function_id):
            ret_val = []

            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_LOCAL_VARS % function_id).fetchall()
                
                for result_row in results:
                    ret_val += {'name':result_row[0]}

            return ret_val             
        
        def select_function_basic_blocks(self, DSN, function_id):
            ret_val = []
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCKS % function_id).fetchall()
                
                for result_row in results:
                    ret_val += result_row[0]

            return ret_val             
        
        def select_function_num_instructions(self, DSN, function_id):
            ret_val = 0
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_FUNCTION_NUM_INSTRUCTIONS % function_id).fetchone()
                ret_val = results[0]

            return ret_val            
            
        def select_function_num_vars(self, DSN, function_id, var_type):
            ret_val = 0
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_FUNCTION_NUM_VARS % (function_id, var_type)).fetchone()
                ret_val = results[0]

            return ret_val
        
        def select_function_basic_block_by_address(self, DSN, function_id, address):
            ret_val = None
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                result = curs.execute(pida.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCK_BY_ADDRESS % (function_id, address, address)).fetchone()
                if result:
                    ret_val = result[0]

            return ret_val   

        def select_function_basic_block_references(self, DSN, function_id):
            '''
            Returns a list of tuples consisting of the source basic block address and the destination basic block address.
            '''
            ret_val = []
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_FUNCTION_BASIC_BLOCK_REFERENCES % (function_id, function_id)).fetchall()
                for result_row in results:
                    ret_val += (result_row[0], result_row[1])

            return ret_val   
        
        def update_function_start_address(self, DSN, function_id, address):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_START_ADDRESS % (address, function_id))
                curs.commit()             
        
        def update_function_end_address(self, DSN, function_id, address):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_END_ADDRESS % (address, function_id))
                curs.commit()             
        
        def update_function_flags(self, DSN, function_id, flags):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_FLAGS % (size, function_id))
                curs.commit()             
                
        def update_function_arg_size(self, DSN, function_id, size):        
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_ARG_SIZE % (size, function_id))
                curs.commit()                    
        
        def update_function_name(self, DSN, function_id, name):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                if name:
                    name = "'" + name.replace("'",  "''") + "'"
                else:
                    name = "NULL"
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_NAME % (name, function_id))
                curs.commit()            
        
        def update_function_saved_reg_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_SAVED_REG_SIZE % (size, function_id))
                curs.commit()            

        def update_function_frame_size(self, DSN, function_id, size):        
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_FRAME_SIZE % (size, function_id))
                curs.commit()            
        
        def update_function_ret_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_RET_SIZE % (size, function_id))
                curs.commit()            

        
        def update_function_local_var_size(self, DSN, function_id, size):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_FUNCTION_LOCAL_VAR_SIZE % (size, function_id))
                curs.commit()            

        ## MODULE ###
        
        def select_module(self, DSN, module_id):
            ret_val = {}
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_MODULE % module_id).fetchone()
                
                ret_val["name"]         = results[0]
                ret_val["base"]         = results[1]
                ret_val["signature"]    = results[2]
            
            return ret_val
            
        def select_module_function_references(self, DSN, module_id):
            '''
            Returns a list of tuples consisting of the source function address and the destination function address.
            '''
            ret_val = []
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_MODULE_FUNCTION_REFERENCES % (module_id, module_id)).fetchall()
                for result_row in results:
                    ret_val += (result_row[0], result_row[1])

            return ret_val                    

        def select_module_num_functions(self, DSN, module_id):
            ret_val = 0
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_MODULE_NUM_FUNCTIONS % module_id).fetchone()
                ret_val = results[0]

            return ret_val            
        
        def select_module_functions(self, DSN, module_id):
            ret_val = []
            
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                results = curs.execute(pida.sqlite_queries.cSELECT_MODULE_FUNCTIONS % module_id).fetchall()
                
                for result_row in results:
                    ret_val += result_row[0]

            return ret_val

        def update_module_name(self, DSN, module_id, name):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                if name:
                    name = "'" + name.replace("'",  "''") + "'"
                else:
                    name = "NULL"
                curs.execute(pida.sqlite_queries.cUPDATE_MODULE_NAME % (name, module_id))
                curs.commit()                
        
        
        def update_module_base(self, DSN, module_id, base):
            if not isNumber(base):
                base = "NULL"
                
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                curs.execute(pida.sqlite_queries.cUPDATE_MODULE_BASE % (base, module_id))
                curs.commit()    

        def update_module_signature(self, DSN, module_id, signature):
            if DSN[:6] == "mysql:":
                pass
            else: #sqlite
                curs = self.connection(DSN)
                if signature:
                    signature = "'" + signature.replace("'",  "''") + "'"
                else:
                    signature = "NULL"
                curs.execute(pida.sqlite_queries.cUPDATE_MODULE_SIGNATURE % (signature, module_id))
                curs.commit()                

        def connection(self, DSN=None):
            '''
            return the SQL connection object
            '''

            if DSN == None:
                print "DSN missing"
                raise "wtf is the DSN?"
                DSN = self.__active_DSN

            if not self.__sql.has_key(DSN):
                "Connection missing"
                self.__init_connection(DSN)

            return self.__sql[DSN]

        def __init_connection(self, DSN_name):

            print "initing"

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
            #self.connection(DSN) = MySQLdb.connect(host=host, user=username, passwd=password)
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
