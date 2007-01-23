#
# Bak Mei - The Pai Mei Backend
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

'''
@author:       Cameron Hotchkies
@license:      GNU General Public License 2.0 or later
@contact:      chotchkies@tippingpoint.com
@organization: www.tippingpoint.com
'''


SQLITE_CREATE_BAKMEI_SCHEMA = ("""
    CREATE TABLE module (
        id              INTEGER PRIMARY KEY,
        name            varchar(255) NOT NULL,
        base            int UNSIGNED NOT NULL,
        signature       text default '',
        data            blob,
        version         varchar(255) NOT NULL
        )""", """

    CREATE TABLE comments (
        id              INTEGER PRIMARY KEY,
        comment         text NOT NULL,
        next            int UNSIGNED
        )""","""

    CREATE TABLE function (
        id              INTEGER PRIMARY KEY,
        module          int UNSIGNED NOT NULL,
        start_address   int UNSIGNED NOT NULL,
        end_address     int UNSIGNED NOT NULL,
        name            varchar(255) NOT NULL,
        import          int UNSIGNED,
        flags           int UNSIGNED,
        comment         int UNSIGNED
        )""","""

    CREATE TABLE frame_info (
        function        INTEGER PRIMARY KEY,
        saved_reg_size  smallint UNSIGNED,
        frame_size      smallint UNSIGNED,
        ret_size        smallint UNSIGNED,
        local_var_size  smallint UNSIGNED,
        arg_size        smallint UNSIGNED
        )""","""

    CREATE TABLE rpc_data (
        function        INTEGER PRIMARY KEY,
        module          int UNSIGNED NOT NULL,
        uuid            char(36) NOT NULL,
        opcode          int NOT NULL,
        idl             text
        )""","""

    CREATE TABLE import (
        id              INTEGER PRIMARY KEY,
        module          int UNSIGNED NOT NULL,
        name            varchar(255) NOT NULL,
        library         varchar(255) NOT NULL
        )""","""

    CREATE TABLE function_variables (
        id              INTEGER PRIMARY KEY,
        function        int UNSIGNED NOT NULL,
        module          int UNSIGNED NOT NULL,
        name            varchar(255) NOT NULL,
        data_type       varchar(255),
        flags           int UNSIGNED NOT NULL,
        comment         int UNSIGNED,
        offset          int NOT NULL
        )""","""

    CREATE TABLE basic_block (
        id              INTEGER PRIMARY KEY,
        start_address   int UNSIGNED NOT NULL,
        end_address     int UNSIGNED NOT NULL,
        function        int UNSIGNED NOT NULL,
        module          int UNSIGNED NOT NULL,
        comment         int UNSIGNED,
        contiguous      tinyint(1)
        )""","""

    CREATE TABLE instruction (
        id              INTEGER PRIMARY KEY,
        address         int UNSIGNED NOT NULL,
        basic_block     int UNSIGNED NOT NULL,
        function        int UNSIGNED NOT NULL,
        module          int UNSIGNED NOT NULL,
        comment         int UNSIGNED,
        bytes           char(10) NOT NULL,
        mnemonic        varchar(15) NOT NULL,
        operand1        varchar(255),
        operand2        varchar(255),
        operand3        varchar(255)
        )""","""

    CREATE TABLE cross_references (
        id              INTEGER PRIMARY KEY,
        source          int UNSIGNED,
        destination     int UNSIGNED,
        reference_type  int UNSIGNED
        )""","""

    CREATE TABLE data (
        id              INTEGER PRIMARY KEY,
        address         int UNSIGNED,
        data_type       int UNSIGNED,
        value           text
        )""")

cINSERT_INSTRUCTION                         = "INSERT INTO instruction (address, basic_block, function, module, mnemonic, bytes) VALUES (%d, %d, %d, %d, '%s', '%s');"
cINSERT_MODULE                              = "INSERT INTO module (name, base, version) VALUES ('%s', %d, '%s');"
cINSERT_FUNCTION                            = "INSERT INTO function (module, start_address, end_address, name) VALUES (%d, %d, %d, '%s');"
cINSERT_BASIC_BLOCK                         = "INSERT INTO basic_block (start_address, end_address, function, module) VALUES (%d, %d, %d, %d);"
                                            
### INSTRUCTION ###                         
                                            
cSELECT_INSTRUCTION                         = "SELECT address, mnemonic, operand1, operand2, operand3, comment, bytes, basic_block FROM instruction WHERE id = %d;"
                                            
cUPDATE_INSTRUCTION_MNEMONIC                = "UPDATE instruction SET mnemonic=%s where id=%d"
cUPDATE_INSTRUCTION_COMMENT                 = "UPDATE instruction SET comment=%s WHERE id=%d;"
cUPDATE_INSTRUCTION_OPERAND1                = "UPDATE instruction SET operand1=%s WHERE id=%d;"
cUPDATE_INSTRUCTION_OPERAND2                = "UPDATE instruction SET operand2=%s WHERE id=%d;"
cUPDATE_INSTRUCTION_OPERAND3                = "UPDATE instruction SET operand3=%s WHERE id=%d;"
cUPDATE_INSTRUCTION_FLAGS                   = "UPDATE instruction SET flags=%d WHERE id = %d;"
cUPDATE_INSTRUCTION_ADDRESS                 = "UPDATE instruction SET address=%d where id=%d"
cUPDATE_INSTRUCTION_COMMENT                 = "UPDATE instruction SET comment=%s where id=%d"
cUPDATE_INSTRUCTION_BYTES                   = "UPDATE instruction SET bytes=%s where id=%d"

### BASIC BLOCK ###

cSELECT_BASIC_BLOCK                         = "SELECT module, function, start_address, end_address FROM basic_block WHERE id = %d;"
cSELECT_BASIC_BLOCK_NUM_INSTRUCTIONS        = "SELECT count(*) FROM instruction WHERE basic_block = %d;"
cSELECT_BASIC_BLOCK_SORTED_INSTRUCTIONS     = "SELECT id FROM instruction WHERE basic_block = %d ORDER BY address ASC"

cUPDATE_BASIC_BLOCK_START_ADDRESS           = "UPDATE basic_block SET start_address=%d where id=%d"
cUPDATE_BASIC_BLOCK_END_ADDRESS             = "UPDATE basic_block SET end_address=%d where id=%d"

cSELECT_BASIC_BLOCK_INSTRUCTION_REFERENCES  = "SELECT b.address, d.address FROM cross_references AS c, instruction AS b, instruction AS d WHERE c.source = b.id AND c.destination = d.id AND b.basic_block = %d AND d.basic_block = %d AND c.reference_type = 8"


### FUNCTION ###

cSELECT_FUNCTION                            = "SELECT name, module, start_address, end_address FROM function WHERE id = %d;"
cSELECT_FRAME_INFO                          = "SELECT saved_reg_size, frame_size, ret_size, local_var_size, arg_size FROM frame_info WHERE function = %d;"
cSELECT_ARGS                                = "SELECT name FROM function_variables WHERE function = %d AND flags = 1;"
cSELECT_LOCAL_VARS                          = "SELECT name FROM function_variables WHERE function = %d AND flags = 2;"
cSELECT_FUNCTION_BASIC_BLOCKS               = "SELECT id FROM basic_block WHERE function = %d"
cSELECT_FUNCTION_NUM_INSTRUCTIONS           = "SELECT count(*) FROM instruction WHERE function = %d;"
cSELECT_FUNCTION_NUM_VARS                   = "SELECT count(*) FROM function_variables WHERE function = %d AND flags & %d > 0"
cSELECT_FUNCTION_BASIC_BLOCK_BY_ADDRESS     = "SELECT id FROM basic_block WHERE function = %d AND start_address <= %d AND end_address >= %d"
                                            
cSELECT_FUNCTION_BASIC_BLOCK_REFERENCES     = "SELECT b.start_address, d.start_address FROM cross_references AS c, basic_block AS b, basic_block AS d WHERE c.source = b.id AND c.destination = d.id AND b.function = %d AND d.function = %d AND c.reference_type = 4"
                                            
cUPDATE_FUNCTION_START_ADDRESS              = "UPDATE function SET start_address=%d where id=%d"
cUPDATE_FUNCTION_END_ADDRESS                = "UPDATE function SET end_address=%d where id=%d"
cUPDATE_FUNCTION_FLAGS                      = "UPDATE function SET flags=%d WHERE id=%d;"
cUPDATE_FUNCTION_ARG_SIZE                   = "UPDATE frame_info SET arg_size=%d WHERE function=%d;"
cUPDATE_FUNCTION_NAME                       = "UPDATE function SET name=%s where id=%d"
cUPDATE_FUNCTION_SAVED_REG_SIZE             = "UPDATE frame_info SET saved_reg_size=%d where function=%d"
cUPDATE_FUNCTION_FRAME_SIZE                 = "UPDATE frame_info SET frame_size=%d where function=%d"
cUPDATE_FUNCTION_RET_SIZE                   = "UPDATE frame_info SET ret_size=%d where function=%d"
cUPDATE_FUNCTION_LOCAL_VAR_SIZE             = "UPDATE frame_info SET local_var_size=%d where function=%d"
                                            
### MODULE ###                              
                                            
cSELECT_MODULE                              = "SELECT name, base, signature FROM module WHERE id = %d;"
cSELECT_MODULE_NUM_FUNCTIONS                = "SELECT count(*) FROM function WHERE module = %d;"
cSELECT_MODULE_FUNCTIONS                    = "SELECT id FROM function WHERE module = %d"
cSELECT_MODULE_FUNCTION_REFERENCES          = "SELECT b.start_address, d.start_address FROM cross_references AS c, function AS b, function AS d WHERE c.source = b.id AND c.destination = d.id AND b.module = %d AND d.module = %d AND c.reference_type = 1"
                                            
                                            
cUPDATE_MODULE_NAME                         = "UPDATE module SET name=%s where id=%d"
cUPDATE_MODULE_BASE                         = "UPDATE module SET base=%s where id=%d"
cUPDATE_MODULE_SIGNATURE                    = "UPDATE module SET signature=%s where id=%d"