#
# IDA Python Open Binary Database Generation Script
# Dumps the current IDB into a .obd file.
#
# $Id$
#
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
# Copyright (C) 2007 Cameron Hotchkies <chotchkies@tippingpoint.com>
#
# Portions of this code were taken from Sabre Security IDA to SQL exporter.
# by Ero Carrera (c) Sabre-Security 2006	[ero.carrera@sabre-security.com]
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
@author:       Cameron Hotchkies, Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      chotchkies@tippingpoint.com
@organization: www.openrce.org
'''

import time
import re
from bakmei import sql_singleton, sqlite_queries
from pysqlite2 import dbapi2 as sqlite

################################ TODO - Pull these from defines.py #####################################
### XREF TYPES ###
CODE_TO_CODE_FUNCTION       = 1
DATA_TO_FUNCTION            = 2
CODE_TO_CODE_BASIC_BLOCK    = 4
CODE_TO_CODE_INSTRUCTION    = 8

VAR_TYPE_ARGUMENT   = 1
VAR_TYPE_LOCAL      = 2
################################ END TODO ##############################################################

### SQL STATEMENTS ###

UPDATE_FUNCTION_ATTRIBS     = "UPDATE function SET start_address=%d, end_address=%d, name='%s' WHERE id = %d;"

SELECT_BLOCK_FROM_INSN      = "SELECT basic_block FROM instruction WHERE id = %d;"

INSERT_IMPORT               = "INSERT INTO import (name, module, library) VALUES (%s, %d, '');"
INSERT_FRAME_INFO           = "INSERT INTO frame_info (function, saved_reg_size, frame_size, ret_size, local_var_size) VALUES (%d, %d, %d, %d, %d);"
INSERT_INSN_TO_INSN_XREFS   = "INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 8);"
INSERT_BLOC_TO_BLOC_XREFS   = "INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 4);"
INSERT_FUNC_TO_FUNC_XREFS   = "INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 1);"
INSERT_INSN_TO_DATA_XREFS   = "INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 64);"
INSERT_BLOC_TO_DATA_XREFS   = "INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 32);"
INSERT_FUNC_TO_DATA_XREFS   = "INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 16);"
INSERT_DATA_FOR_REFS        = "INSERT INTO data (address, data_type, value) VALUES (%d, '00000000', 1);"

INSERT_INSTRUCTION          = "INSERT INTO instruction (address, basic_block, function, module, mnemonic, bytes) VALUES (%d, %d, %d, %d, %s, %s);"
INSERT_MODULE               = "INSERT INTO module (name, base, version) VALUES (%s, %d, %s);"
INSERT_FUNCTION             = "INSERT INTO function (module, start_address, end_address, name) VALUES (%d, %d, %d, %s);"
INSERT_BASIC_BLOCK          = "INSERT INTO basic_block (start_address, end_address, function, module) VALUES (%d, %d, %d, %d);"
INSERT_OPERAND              = "INSERT INTO operand (instruction, position, operand_text) VALUES (%d, %d, %s);"

def main():
    output_file = AskFile(1, GetInputFile() + ".obdf", "Save OBDF file to?")

    if not output_file:
        Warning("Cancelled.")
    else:
        print "Analyzing IDB..."
        start = time.time()

        try:
            signature = bakmei.signature(GetInputFilePath())
        except:
            print "OBDF.DUMP> Could not calculate signature for %s, perhaps the file was moved?" % GetInputFilePath()
            signature = ""

        create_module(GetInputFile(), signature)

        print "Storing cross-references..."

        set_up_cross_references()

        print "Saving to file...",

        copy_from_memory(output_file)

        print "Done. Completed in %f seconds.\n" % round(time.time() - start, 3)

####################################################################################################################

def find_bb_by_instruction(instruction_id):
    res = curs.execute(SELECT_BLOCK_FROM_INSN % instruction_id).fetchone()

    return res[0]

####################################################################################################################

def set_up_cross_references():
    function_added = {}
    basic_block_added = {}

    for xref in global_branches.keys():
        try:
            id_tuple_source = instruction_address_lookup[xref[0]]
            id_tuple_dest   = instruction_address_lookup[xref[1]]
            curs.execute(INSERT_INSN_TO_INSN_XREFS % (id_tuple_source[0], id_tuple_dest[0]))

            if not basic_block_added.has_key((id_tuple_source[1], id_tuple_dest[1])):
                curs.execute(INSERT_BLOC_TO_BLOC_XREFS % (id_tuple_source[1], id_tuple_dest[1]))
                basic_block_added[(id_tuple_source[1], id_tuple_dest[1])] = 1

                if id_tuple_source[2] != id_tuple_dest[2] and not function_added.has_key((id_tuple_source[2], id_tuple_dest[2])):
                    curs.execute(InSERT_BLOC_TO_BLOC_XREFS % (id_tuple_source[2], id_tuple_dest[2]))
                    function_added[(id_tuple_source[2], id_tuple_dest[2])] = 1

        except KeyError, details:
            # TODO pick up all this lost code (Mainly thunks and unfunctioned code)
            print "Missing instruction for 0x%08x / 0x%08x - It's probably not in a defined function. Skipping." % xref

    # Build Data XRefs

    function_added = {}
    basic_block_added = {}

    for dref in global_drefs.keys():
        try:
            id_tuple_source = instruction_address_lookup[dref[0]]

            curs.execute(INSERT_INSN_TO_DATA_XREFS % (id_tuple_source[0], dref[1]))

            if not basic_block_added.has_key((id_tuple_source[1], dref[1])):
                curs.execute(INSERT_BLOC_TO_DATA_XREFS % (id_tuple_source[1], dref[1]))
                basic_block_added[(id_tuple_source[1], dref[1])] = 1

                if id_tuple_source[2] != id_tuple_dest[2] and not function_added.has_key((id_tuple_source[2], dref[1])):
                    curs.execute(INSERT_FUNC_TO_DATA_XREFS % (id_tuple_source[2], dref[1]))
                    function_added[(id_tuple_source[2], id_tuple_dest[2])] = 1

        except KeyError, details:
            # TODO pick up all this lost code (Mainly thunks and unfunctioned code)
            print "0x%08x: Missing instruction for Data Ref." % dref[0]

    sql_connection.commit()

####################################################################################################################

def copy_from_memory(filename):
    outfile = filename

    if os.path.exists(outfile):
        os.remove(outfile)

    curs.execute("ATTACH DATABASE '%s' AS extern;" % outfile)

    for tbl in sqlite_queries.SQLITE_CREATE_BAKMEI_SCHEMA:
        tb2 = tbl.replace("TABLE ", "TABLE extern.")

        curs.execute(tb2)

        tblname = tb2.split("extern.")[1].split(' ')[0]

        sql = "INSERT INTO extern.%s SELECT * FROM %s;" % (tblname, tblname)
        curs.execute(sql)

    sql_connection.commit()

    print "closing the database [%s]" % outfile

    sql_connection.close()

####################################################################################################################

def enumerate_imports (module_id):
    """
    Enumerate and add nodes / edges for each import within the module. This routine only checks the .idata section

    This code was blatantly stolen from Cody's get_lib_calls script
    """

    seg_start = SegByName(".idata")
    seg_end = SegEnd(seg_start)

    # Set first import address
    import_ea = seg_start

    # Do not leave the .idata segment
    while import_ea < seg_end:

        #Get the name of the imported function
        import_name = Name(import_ea);

        if len(import_name) > 1:
            # TODO : Save the library name as well
            curs.execute(INSERT_IMPORT % (ss.sql_safe_str(import_name), module_id))
            import_id = curs.lastrowid

            sql = ss.INSERT_FUNCTION % (module_id, import_ea, import_ea, ss.sql_safe_str(import_name))
            curs.execute(sql)
            dbid = curs.lastrowid

            curs.execute("UPDATE function SET import=%d WHERE id=%d;" % (import_id, dbid))

            sql_connection.commit()

            # Set up Data References
            curs.execute(INSERT_DATA_FOR_REFS % import_ea)

            import_id = curs.lastrowid

            for refs in DataRefsTo(import_ea):
                global_drefs[(refs, import_id)] = 1

        # Advance to the next import
        import_ea += 4

    # TODO also grab THUNKS


# REDEFINE PROPERLY

NODE_TYPE_OPERATOR_WIDTH_BYTE_1         = 'b1'    # Byte
NODE_TYPE_OPERATOR_WIDTH_BYTE_2         = 'b2'    # Word
NODE_TYPE_OPERATOR_WIDTH_BYTE_3         = 'b3'    #
NODE_TYPE_OPERATOR_WIDTH_BYTE_4         = 'b4'    # Double-Word
NODE_TYPE_OPERATOR_WIDTH_BYTE_5         = 'b5'    #
NODE_TYPE_OPERATOR_WIDTH_BYTE_6         = 'b6'    #
NODE_TYPE_OPERATOR_WIDTH_BYTE_7         = 'b7'    #
NODE_TYPE_OPERATOR_WIDTH_BYTE_8         = 'b8'    # Quad-Word
NODE_TYPE_OPERATOR_WIDTH_BYTE_9         = 'b9'    #
NODE_TYPE_OPERATOR_WIDTH_BYTE_10        = 'b10'   #
NODE_TYPE_OPERATOR_WIDTH_BYTE_12        = 'b12'   # Packed Real Format mc68040
NODE_TYPE_OPERATOR_WIDTH_BYTE_14        = 'b14'   #
NODE_TYPE_OPERATOR_WIDTH_BYTE_16        = 'b16'   #
NODE_TYPE_OPERATOR_WIDTH_BYTE_VARIABLE  = 'b_var' # Variable size

OPERAND_WIDTH = {
    0 : ("dt_byte"    , NODE_TYPE_OPERATOR_WIDTH_BYTE_1),           ## 8 bit
    1 : ("dt_word"    , NODE_TYPE_OPERATOR_WIDTH_BYTE_2),           ## 16 bit
    2 : ("dt_dword"   , NODE_TYPE_OPERATOR_WIDTH_BYTE_4),           ## 32 bit
    3 : ("dt_float"   , NODE_TYPE_OPERATOR_WIDTH_BYTE_4),           ## 4 byte
    4 : ("dt_double"  , NODE_TYPE_OPERATOR_WIDTH_BYTE_8),           ## 8 byte
    5 : ("dt_tbyte"   , NODE_TYPE_OPERATOR_WIDTH_BYTE_VARIABLE),    ## variable size (ph.tbyte_size)
    6 : ("dt_packreal", NODE_TYPE_OPERATOR_WIDTH_BYTE_12),          ## packed real format for mc68040
    7 : ("dt_qword"   , NODE_TYPE_OPERATOR_WIDTH_BYTE_8),           ## 64 bit
    8 : ("dt_byte16"  , NODE_TYPE_OPERATOR_WIDTH_BYTE_16),          ## 128 bit
    9 : ("dt_code"    , ""),                                        ## ptr to code (not used?)
    10: ("dt_void"    , ""),                                        ## none
    11: ("dt_fword"   , NODE_TYPE_OPERATOR_WIDTH_BYTE_6),           ## 48 bit
    12: ("dt_bitfild" , ""),                                        ## bit field (mc680x0)
    13: ("dt_string"  , ""),                                        ## pointer to asciiz string
    14: ("dt_unicode" , ""),                                        ## pointer to unicode string
    15: ("dt_3byte"   , NODE_TYPE_OPERATOR_WIDTH_BYTE_3)            ## 3-byte data
                }

NODE_TYPE_MNEMONIC_ID =         0
NODE_TYPE_SYMBOL_ID =           1
NODE_TYPE_IMMEDIATE_INT_ID =    2
NODE_TYPE_IMMEDIATE_FLOAT_ID =  3
NODE_TYPE_OPERATOR_ID =         4

NODE_TYPE_OPERATOR_PLUS         = '+'
NODE_TYPE_OPERATOR_MINUS        = '-'
NODE_TYPE_OPERATOR_TIMES        = '*'
NODE_TYPE_OPERATOR_DEREFERENCE  = '['
NODE_TYPE_OPERATOR_LIST         = '{'

SIB_BASE_REGISTERS = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

REGISTERS    = [
        [   'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'ip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [   'ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'ip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [   'eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'eip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'],
        [   'rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', 'r8',
            'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'al',
            'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', 'spl', 'bpl',
            'sil', 'dil', 'rip', 'es', 'cs', 'ss', 'ds', 'fs', 'gs'] ]



####################################################################################################################

def create_expression_entry(expression_type, symbol, immediate, position, parent_id):
    return [position, expression_type, symbol, immediate, position, parent_id]

####################################################################################################################

def create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea):
    index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]

    tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))

    if base_reg != '':
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
        seg_off += 1

    tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_TIMES, None, 3+seg_off, 2+seg_off))
    tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, index_reg, None, 4+seg_off, 3+seg_off))
    tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, scale, 5+seg_off, 3+seg_off))

####################################################################################################################

def get_stack_variable(ida_op, ea):
    if ida_op.addr>2**31:
        addr = -(2**32 - ida_op.addr)
    else:
        addr = ida_op.addr
    skvar = get_stkvar(ida_op, addr, None)

    # Sometimes the flags misrepresent, just gotta be safe
    if not skvar:
        return (None, 0)

    func = get_func(ea)

    offset = calc_stkvar_struc_offset(func, ea, ord(ida_op.n))

    varegex = re.compile(r'.*fr[0-9a-f]+\.(.*)')

    try:
        name = varegex.match(get_struc_name(skvar.id)).group(1)
    except:
        print "0x%08x: Stack Variable with no name" % ea
        name = ""

    return (name, offset - skvar.soff)

####################################################################################################################

def create_operand(instruction_id, ea, position):
    op  = GetOpnd(ea, position)

    sql = ss.INSERT_OPERAND % (instruction_id, position, ss.sql_safe_str(op))

    curs.execute(sql)
    dbid = curs.lastrowid

    op_type = GetOpType(ea, position)

    ida_op = get_instruction_operand(get_current_instruction(), position)

    index = 0

    op_width = OPERAND_WIDTH[ord(ida_op.dtyp)]

    root = create_expression_entry(NODE_TYPE_OPERATOR_ID, op_width, None, 0, None)
    root[0] = 0

    tree = [root]

    if op_width[1] == "":
        raise NotImplementedError, "Missing operand width for %s" % op_width[0]

    if op_type == 1:
        # General Register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, op, None, 1, 0))
    elif op_type == 2:
        # Memory Reference
        create_memory_reference_operand(tree, ida_op, op, ea)
    elif op_type == 3:
        # Phrase (Base + Index)
        create_phrase_operand(tree, ida_op, op, ea)
    elif op_type == 4:
        # (+) Displacement
        create_displ_operand(tree, ida_op, op, ea)
    elif op_type == 5:
        # Immediate
        # TODO: String references aren't being saved.. Fix this
        tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, GetOperandValue(ea, position), 1, 0))
    elif op_type in (6, 7):
        # Immediate (Far, Near) Address
        # TODO: save substitution of ptr addresses
        tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr,  1, 0))
    elif op_type == 11:
        # 386 Trace Register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, 'st(%d)' % ida_op.reg, None, 1, 0))
    elif op_type == 12:
        # MMX register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, 'mm%d' % ida_op.reg, None, 1, 0))
    elif op_type == 13:
        # XMM register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, 'xmm%d' % ida_op.reg, None, 1, 0))
    else:
        print "0x%08x: Gonna die..." % ea
        raise NotImplementedError, "Currently can not process %d operands" % op_type

    if len(tree) == 1:
        print "0x%08x: Gonna die..." % ea
        raise NotImplementedError, "No operands for %d operands" % op_type

    #TODO Insert into database
    INSERT_EXPRESSION = "INSERT INTO expression (expr_type, symbol, immediate, position, parent_id) VALUES (%d, %s, %s, %d, %s)"

    parent_lookup = {}
    for entry in tree:
        sql = INSERT_EXPRESSION % (entry[1], ss.sql_safe_str(entry[2]) if entry[2] else "NULL",
            ss.sql_safe_str(entry[3]) if entry[3] else "NULL", entry[4],
            parent_lookup[entry[5]] if entry[5] else "NULL")
        curs.execute(sql)
        expr_id = curs.lastrowid
        parent_lookup[entry[0]] = expr_id

        # TODO : now might be a good time to eliminate dupes


####################################################################################################################

def create_memory_reference_operand(tree, ida_op, temp, ea):
    # TODO: Save the address name
    seg_off = 0

    if ida_op.specval>>16 != 0:
        segment_prefix = REGISTERS[0][ida_op.specval>>16]

        tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, segment_prefix, None, 1, 0))
        seg_off = 1

    tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_DEREFERENCE, None, 1+seg_off, 0+seg_off))

    # Is there an SIB byte?
    if ord(ida_op.specflag1)==1:
        base_reg = SIB_BASE_REGISTERS[ord(ida_op.specflag2)&0x7]

        if base_reg == 'ebp' and temp.find('ebp') < 0:
            base_reg = ''

        scale = (None, 2, 4, 8)[ord(ida_op.specflag2)>>6]

        if scale:
            plus_off = 2+seg_off # seg_off can be changed by the following function
            create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea)
            tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
        else:
            index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]

            if index_reg != "esp":
                print "0x%08x: Gonna die..." % ea
                raise NotImplementedError, "Don't know how to handle index registers"
            else:
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
                # TODO: save substitution
    else:
        tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 1+seg_off, 0+seg_off))

####################################################################################################################

def create_phrase_operand(tree, ida_op, temp, ea):
    seg_off = 0

    if ida_op.specval>>16 != 0:
        segment_prefix = REGISTERS[0][ida_op.specval>>16]

        tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, segment_prefix, None, 1, 0))
        seg_off = 1

    tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_DEREFERENCE, None, 1+seg_off, 0+seg_off))

    # Is there an SIB byte?
    if ord(ida_op.specflag1)==1:

        base_reg = SIB_BASE_REGISTERS[ord(ida_op.specflag2)&0x7]

        if base_reg == 'ebp' and temp.find('ebp') < 0:
            base_reg = ''

        scale = (None, 2, 4, 8)[ord(ida_op.specflag2)>>6]

        if scale:
            create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea)
            # Is there a value at the end?
        else:
            index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]

            if index_reg == "esp":
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
            else:
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, index_reg, None, 4+seg_off, 2+seg_off))

                # TODO: save substitution

    else:
        reg = REGISTERS[getseg(ea).bitness+1][ida_op.phrase]
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, reg, None, 3+seg_off, 2+seg_off))

####################################################################################################################

def create_displ_operand(tree, ida_op, temp, ea):
    seg_off = 0

    if ida_op.specval>>16 != 0:
        segment_prefix = REGISTERS[0][ida_op.specval>>16]

        tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, segment_prefix, None, 1, 0))
        seg_off = 1

    tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_DEREFERENCE, None, 1+seg_off, 0+seg_off))

    # Check for a variable name
    # TODO : Now would be a good time to insert vars into the database
    flags = GetFlags(ea)

    var_name    = None
    offset_adj  = 0

    if (ord(ida_op.n) == 0 and isStkvar0(flags)) or (ord(ida_op.n) == 1 and isStkvar0(flags)):
        var_name, offset_adj = get_stack_variable(ida_op, ea)

    value = long(ida_op.addr)

    # Is there an SIB byte?
    if ord(ida_op.specflag1)==1:
        base_reg = SIB_BASE_REGISTERS[ord(ida_op.specflag2)&0x7]

        if base_reg == 'ebp' and temp.find('ebp') < 0:
            base_reg = ''

        scale = (None, 2, 4, 8)[ord(ida_op.specflag2)>>6]

        if scale:
            plus_off = 2+seg_off # seg_off can be changed by the following function
            create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea)
            tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
        else:
            index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]

            if index_reg != "esp":
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, index_reg, None, 4+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 5+seg_off, 2+seg_off))
                # TODO: save substitution
            else:
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 4+seg_off, 2+seg_off))
                # TODO: save substitution
    else:
       tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
       reg = REGISTERS[getseg(ea).bitness+1][ida_op.reg]
       tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, reg, None, 3+seg_off, 2+seg_off))
       tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 4+seg_off, 2+seg_off))
       # TODO: save substitution (if any)

####################################################################################################################

def create_operands(instruction_id, ea):
    # instruction mnemonic and operands.

    for op_num in (0,1,2):
        oper = GetOpnd(ea, op_num)

        if oper != None and oper != "":
            create_operand(instruction_id, ea, op_num)
        else:
            return

####################################################################################################################

def create_instruction (ea, basic_block_id, function_id, module_id):
    '''
    Analyze the instruction at ea.

    @see: defines.py

    @type  ea:          DWORD
    @param ea:          Effective address of instruction to analyze
    @type  basic_block: pgraph.basic_block
    @param basic_block: (Optional, Def=None) Pointer to parent basic block container
    '''

    # raw instruction bytes.
    bytes = ""

    for address in xrange(ea, ItemEnd(ea)):
        temp_byte = hex(Byte(address))[2:]
        if len(temp_byte) < 2:
            temp_byte = "0" + temp_byte
        bytes += temp_byte

    sql = INSERT_INSTRUCTION % (ea, basic_block_id, function_id, module_id, ss.sql_safe_str(GetMnem(ea)), ss.sql_safe_str(bytes))

    curs.execute(sql)
    dbid = curs.lastrowid

    instruction_address_lookup[ea] = (dbid, basic_block_id, function_id)

    comment = Comment(ea)
    if comment != None:
        ss.update_instruction_comment(global_DSN, dbid, comment)

    create_operands(dbid, ea)

    return dbid

####################################################################################################################

def create_basic_block (ea_start, ea_end, function_id, module_id):
    '''
    Analyze the basic block from ea_start to ea_end.

    @see: defines.py

    @type  ea_start: DWORD
    @param ea_start: Effective address of start of basic block (inclusive)
    @type  ea_end:   DWORD
    @param ea_end:   Effective address of end of basic block (inclusive)
    @type  function: bakmei.function
    @param function: (Optional, Def=None) Pointer to parent function container
    '''

    heads = [head for head in Heads(ea_start, ea_end + 1) if isCode(GetFlags(head))]

    sql = INSERT_BASIC_BLOCK % ( ea_start, ea_end, function_id, module_id)
    curs.execute(sql)

    dbid = curs.lastrowid

    for ea in heads:
        create_instruction(ea, dbid, function_id, module_id)

    sql_connection.commit()

##################################################################################################################

def branches_from (ea):
    '''
    Enumerate and return the list of branches from the supplied address, *including* the next logical instruction.
    Part of the reason why we even need this function is that the "flow" argument to CodeRefsFrom does not appear
    to be functional.

    @type  ea: DWORD
    @param ea: Effective address of instruction to enumerate jumps from.

    @rtype:  List
    @return: List of branches from the specified address.
    '''

    xrefs = CodeRefsFrom(ea, 1)

    # if the only xref from ea is next ea, then return nothing.
    if len(xrefs) == 1 and xrefs[0] == NextNotTail(ea):
        xrefs = []

    for xr in xrefs:
        global_branches[(ea, xr)] = 1

    return xrefs


####################################################################################################################

def branches_to (ea):
    '''
    Enumerate and return the list of branches to the supplied address, *excluding* the previous logical instruction.
    Part of the reason why we even need this function is that the "flow" argument to CodeRefsTo does not appear to
    be functional.

    @type  ea: DWORD
    @param ea: Effective address of instruction to enumerate jumps to.

    @rtype:  List
    @return: List of branches to the specified address.
    '''

    xrefs        = []
    prev_ea      = PrevNotTail(ea)
    prev_code_ea = prev_ea

    while not isCode(GetFlags(prev_code_ea)):
        prev_code_ea = PrevNotTail(prev_code_ea)

    for xref in CodeRefsTo(ea, 1):
        if xref not in [prev_ea, prev_code_ea]: # not is_call_insn(xref) and
            xrefs.append(xref)
            global_branches[(xref, ea)] = 1

    return xrefs

####################################################################################################################

def uuid_bin_to_string (uuid):
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

def enumerate_rpc (module_id):
    '''
    Enumerate all RPC interfaces and add additional properties to the RPC functions. This routine will pass through
    the entire IDA database. This was entirely ripped from my RPC enumeration IDC script:

        http://www.openrce.org/downloads/details/3/RPC%20Enumerator

    The approach appears to be stable enough.
    '''

    # walk through the entire database.
    # we don't just look at .text as .rdata also been spotted to house RPC structs.
    for loop_ea in Heads(MinEA(), MaxEA()):
        ea     = loop_ea;
        length = Byte(ea);
        magic  = Dword(ea + 0x18);

        # RPC_SERVER_INTERFACE found.
        if length == 0x44 and magic == 0x8A885D04:
            print "found RPC section"
            # grab the rpc interface uuid.
            uuid = ""
            for x in xrange(ea+4, ea+4+16):
                uuid += chr(Byte(x))

            # jump to MIDL_SERVER_INFO.
            ea = Dword(ea + 0x3C);

            # jump to DispatchTable.
            ea = Dword(ea + 0x4);

            # enumerate the dispatch routines.
            opcode = 0
            while 1:
                addr = Dword(ea)

                if addr == BADADDR:
                    break

                # sometimes ida doesn't correctly get the function start thanks to the whole 'mov reg, reg' noop
                # nonsense. so try the next instruction.
                if not len(GetFunctionName(addr)):
                    addr = NextNotTail(addr)

                    if not len(GetFunctionName(addr)):
                        break

                function_id = curs.execute("SELECT id FROM function WHERE start_address=%d AND module = %d;" % (addr, module_id)).fetchone()[0]

                if function_id:
                    curs.execute("INSERT INTO rpc_data (function, module, uuid, opcode) VALUES (%d, %d, '%s', %d);" % (function_id, module_id, uuid_bin_to_string(uuid), opcode))
                else:
                    print "BAKMEI.MODULE> No function node for RPC routine @%08X" % addr

                ea     += 4
                opcode += 1

####################################################################################################################

def init_basic_blocks (ea_start, function_id, module_id):
    '''
    Enumerate the basic block boundaries for the current function and store them in a graph structure.
    Partly stolen from Ero
    '''
    chunks   = []
    iterator = func_tail_iterator_t(get_func(ea_start))
    status   = iterator.main()

    while status:
        chunk = iterator.chunk()
        chunks.append((chunk.startEA, chunk.endEA))
        status = iterator.next()

    for (chunk_start, chunk_end) in chunks:
        block_start = chunk_start

        # enumerate the nodes.
        for ea in Heads(chunk_start, chunk_end):
            # ignore data heads.
            if not isCode(GetFlags(ea)):
                continue

            prev_ea       = PrevNotTail(ea)
            next_ea       = NextNotTail(ea)

            br_to   = branches_to(ea)
            br_from = branches_from(ea)

            # ensure that both prev_ea and next_ea reference code and not data.
            while not isCode(GetFlags(prev_ea)):
                prev_ea = PrevNotTail(prev_ea)

            while not isCode(GetFlags(next_ea)):
                next_ea = PrevNotTail(next_ea)

            # if the current instruction is a ret instruction, end the current node at ea.
            # if there is a branch from the current instruction, end the current node at ea.
            if is_ret_insn(ea) or br_from or chunk_end == next_ea:
                bb = create_basic_block(block_start, ea, function_id, module_id)

                # start a new block at the next ea.
                block_start = next_ea

            # if there is a branch to the current instruction, end the current node at previous ea.
            elif br_to and block_start != ea:
                bb = create_basic_block(block_start, prev_ea, function_id, module_id)

                # start a new block at ea.
                block_start = ea
            else:
                pass

####################################################################################################################

def init_args_and_local_vars (func_struct, frame_struct, function_id, module_id):
    '''
    Calculate the total size of arguments, # of arguments and # of local variables. Update the internal class member
    variables appropriately.
    '''

    if not frame_struct:
        return

    saved_reg_size = func_struct.frregs
    frame_size     = get_frame_size(func_struct)
    ret_size       = get_frame_retsize(func_struct)
    local_var_size = func_struct.frsize

    argument_boundary = local_var_size + saved_reg_size + ret_size
    frame_offset      = 0

    for i in xrange(0, frame_struct.memqty):
        end_offset = frame_struct.get_member(i).soff

        if i == frame_struct.memqty - 1:
            begin_offset = frame_struct.get_member(i).eoff
        else:
            begin_offset = frame_struct.get_member(i+1).soff

        frame_offset += (begin_offset - end_offset)

        # grab the name of the current local variable or argument.
        name = get_member_name(frame_struct.get_member(i).id)

        vtype = -1

        if frame_offset > argument_boundary:
            vtype = VAR_TYPE_ARGUMENT
        else:
            # if the name starts with a space, then ignore it as it is either the stack saved ebp or eip.
            # XXX - this is a pretty ghetto check.
            if not name.startswith(" "):
                vtype = VAR_TYPE_LOCAL

        if vtype != -1:
            curs.execute("INSERT INTO function_variables (function, module, name, flags, offset) VALUES (%d, %d, '%s', %d, %d);" %(function_id, module_id, ss.sql_safe_str(name), vtype, end_offset))

    arg_size = frame_offset - argument_boundary
    ss.update_function_arg_size(global_DSN, function_id, arg_size)

####################################################################################################################

def create_module(name, signature=None):
    sql = ss.INSERT_MODULE % (ss.sql_safe_str(name), MinEA() - 0x1000, "'0'")

    curs.execute(sql)
    module_id = curs.lastrowid

    sql_connection.commit()

    log = True

    # enumerate and add the functions within the module.
    if log:
        print "Analyzing %d functions..." % len(Functions(MinEA(), MaxEA()))

    for ea in Functions(MinEA(), MaxEA()):
        func = create_function(ea, module_id)

    # enumerate and add nodes for each import within the module.
    if log:
        print"Enumerating imports..."

    enumerate_imports(module_id)

    # enumerate and propogate attributes for any discovered RPC interfaces.
    if log:
        print "Enumerating RPC interfaces..."

    enumerate_rpc(module_id)

    # enumerate and add the intramodular cross references.
    if log:
        print "Enumerating intramodular cross references..."

####################################################################################################################

def create_function (ea_start, module_id=0):
    # The end address is the same as the start address for the insertion
    sql = ss.INSERT_FUNCTION % (module_id, ea_start, ea_start, "''")

    curs.execute(sql)
    dbid = curs.lastrowid

    sql_connection.commit()

    # grab the ida function and frame structures.
    func_struct  = get_func(ea_start)
    frame_struct = get_frame(func_struct)

    # grab the function flags.
    flags = GetFunctionFlags(ea_start)
    ss.update_function_flags(global_DSN, dbid, flags)

    if not func_struct:
        print "0x%08x: [X] Bad Function?" % ea_start

    ea_start       = func_struct.startEA
    ea_end         = PrevAddr(func_struct.endEA)
    name           = GetFunctionName(ea_start)

    curs.execute(UPDATE_FUNCTION_ATTRIBS % (ea_start, ea_end, ss.sql_safe_str(name), dbid))

    saved_reg_size = func_struct.frregs
    frame_size     = get_frame_size(func_struct)
    ret_size       = get_frame_retsize(func_struct)
    local_var_size = func_struct.frsize

    curs.execute(INSERT_FRAME_INFO % (dbid, saved_reg_size, frame_size, ret_size, local_var_size))

    chunks         = [(ea_start, ea_end)]

    init_args_and_local_vars(func_struct, frame_struct, dbid, module_id)

    init_basic_blocks(ea_start, dbid, module_id)

    return dbid

####################################################################################################################

ss = sql_singleton.sql_singleton()
global_DSN = ":memory:"
sql_connection = ss.connection(global_DSN)
curs = sql_connection.cursor()

# Initialize global BB edges list
global_branches = {}
global_drefs = {}
instruction_address_lookup = {}


main()