#
# IDA Python Open Binary Database Generation Script
# Dumps the current IDB into a .obd file.
#
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

'''
@author:       Cameron Hotchkies, Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      chotchkies@tippingpoint.com
@organization: www.openrce.org
'''

import time
import pida
from pysqlite2 import dbapi2 as sqlite

DEPTH_FUNCTIONS    = 0x0001
DEPTH_BASIC_BLOCKS = 0x0002
DEPTH_INSTRUCTIONS = 0x0004
DEPTH_FULL         = DEPTH_FUNCTIONS | DEPTH_BASIC_BLOCKS | DEPTH_INSTRUCTIONS

ANALYSIS_NONE      = 0x0000
ANALYSIS_IMPORTS   = 0x0001
ANALYSIS_RPC       = 0x0002
ANALYSIS_FULL      = ANALYSIS_IMPORTS | ANALYSIS_RPC


################################ TODO - Pull these from defines.py #####################################
### XREF TYPES ###
CODE_TO_CODE_FUNCTION       = 1
DATA_TO_FUNCTION            = 2
CODE_TO_CODE_BASIC_BLOCK    = 4
CODE_TO_CODE_INSTRUCTION    = 8

VAR_TYPE_ARGUMENT   = 1
VAR_TYPE_LOCAL      = 2
################################ END TODO ##############################################################

def main():
    depth    = None
    analysis = ANALYSIS_NONE

    depth = DEPTH_FULL
    analysis |= ANALYSIS_IMPORTS

    analysis |= ANALYSIS_RPC


    output_file = AskFile(1, GetInputFile() + ".obdf", "Save OBDF file to?")


    if not output_file:
        Warning("Cancelled.")
    else:
        for tbl in pida.SQLITE_CREATE_PIDA_SCHEMA:
            curs.execute(tbl)

        print "Analyzing IDB..."
        start = time.time()

        try:
            signature = pida.signature(GetInputFilePath())
        except:
            print "OBDF.DUMP> Could not calculate signature for %s, perhaps the file was moved?" % GetInputFilePath()
            signature = ""

        create_module(GetInputFile(), signature, depth, analysis)

        print "Storing cross-references..."

        set_up_cross_references()

        print "Saving to file...",

        copy_from_memory(output_file)

        print "Done. Completed in %f seconds.\n" % round(time.time() - start, 3)

def find_bb_by_instruction(instruction_id):
    res = curs.execute("SELECT basic_block FROM instruction WHERE id = %d;" % instruction_id).fetchone()

    return res[0]

def set_up_cross_references():
    function_added = {}
    basic_block_added = {}

    for xref in global_branches.keys():
        try:
            id_tuple_source = instruction_address_lookup[xref[0]]
            id_tuple_dest   = instruction_address_lookup[xref[1]]
            curs.execute("INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 8);" % (id_tuple_source[0], id_tuple_dest[0]))

            if not basic_block_added.has_key((id_tuple_source[1], id_tuple_dest[1])):
                if id_tuple_source[1] == 50:
                    print "saving %d to %d" % (50, id_tuple_dest[1])
                curs.execute("INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 4);" % (id_tuple_source[1], id_tuple_dest[1]))
                basic_block_added[(id_tuple_source[1], id_tuple_dest[1])] = 1

                if id_tuple_source[2] != id_tuple_dest[2] and not function_added.has_key((id_tuple_source[2], id_tuple_dest[2])):
                    curs.execute("INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, 1);" % (id_tuple_source[2], id_tuple_dest[2]))
                    function_added[(id_tuple_source[2], id_tuple_dest[2])] = 1

        except KeyError, details:
            # TODO pick up all this lost code
            print "Missing instruction for 0x%08x / 0x%08x - It's probably not in a defined function. Skipping." % xref
    sql_connection.commit()

def copy_from_memory(filename):
    outfile = filename

    if os.path.exists(outfile):
        os.remove(outfile)

    curs.execute("ATTACH DATABASE '%s' AS extern;" % outfile)

    for tbl in pida.SQLITE_CREATE_PIDA_SCHEMA:
        tb2 = tbl.replace("TABLE ", "TABLE extern.")

        curs.execute(tb2)

        tblname = tb2.split("extern.")[1].split(' ')[0]

        sql = "INSERT INTO extern.%s SELECT * FROM %s;" % (tblname, tblname)
        curs.execute(sql)

    sql_connection.commit()

    print "closing the database [%s]" % outfile

    sql_connection.close()

####################################################################################################################
def enumerate_imports ():
    '''
    Enumerate and add nodes / edges for each import within the module. This routine will pass through the entire
    module structure.
    '''

    #for all instructions:
    #    if instruction.refs_api:
    #        (address, api) = instruction.refs_api
    #
    #        node = function(address, module=self)
    #        self.add_node(node)
    #
    #        edge = pgraph.edge.edge(func.ea_start, address)
    #        self.add_edge(edge)

    # TODO this seems like a SQL query.. ask pedram
    pass

####################################################################################################################
def _get_arg_ref (ea):
    '''
    Return the stack offset of the argument referenced, if any, by the instruction.

    @author: Peter Silberman

    @rtype:  Mixed
    @return: Referenced argument stack offset or None.
    '''

    func = get_func(ea)

    if not func:
        return None

    # determine if either of the operands references a stack offset.
    op_num = 0
    offset = calc_stkvar_struc_offset(func, ea, 0)

    if offset == BADADDR:
        op_num = 1
        offset = calc_stkvar_struc_offset(func, ea, 1)

        if offset == BADADDR:
            return None

    # for some reason calc_stkvar_struc_offset detects constant values as an index into the stack struct frame. we
    # implement this check to ignore this false positive.
    # XXX - may want to look into why this is the case later.
    if _get_constant_ref(ea, op_num):
        return None

    #TODO Sort out
    #if self.basic_block.function.args.has_key(offset):
    #    return self.basic_block.function.args[offset]

    return None


####################################################################################################################
def _get_constant_ref (ea, opnum=0):
    '''
    Return the constant value, if any, reference by the instruction.

    @author: Peter Silberman

    @rtype:  Mixed
    @return: Integer value of referenced constant, otherwise None.
    '''

    instruction = idaapi.get_current_instruction()

    if not instruction:
        return None

    if opnum:
        op0 = idaapi.get_instruction_operand(instruction, opnum)

        if op0.value and op0.type == o_imm and GetStringType(ea) == None:
            return op0.value

    else:
        op0 = idaapi.get_instruction_operand(instruction, 0)

        if op0.value and op0.type == o_imm and GetStringType(ea) == None:
            return op0.value

        op1 = idaapi.get_instruction_operand(instruction, 1)

        if op1.value and op1.type == o_imm and GetStringType(ea) == None:
            return op1.value

    return None


####################################################################################################################
def _get_var_ref (ea):
    '''
    Return the stack offset of the local variable referenced, if any, by the instruction.

    @author: Peter Silberman

    @rtype:  Mixed
    @return: Referenced local variable stack offset or None.
    '''

    func = get_func(ea)

    if not func:
        return None

    # determine if either of the operands references a stack offset.
    op_num = 0
    offset = calc_stkvar_struc_offset(func, ea, 0)

    if offset == BADADDR:
        op_num = 1
        offset = calc_stkvar_struc_offset(func, ea, 1)

        if offset == BADADDR:
            return None

# TODO Sort out
#    if self.basic_block.function.local_vars.has_key(offset):
#        return self.basic_block.function.local_vars[offset]

    return None


####################################################################################################################
def get_string_reference (ea):
    '''
    If the specified instruction references a string, get and return the contents of that string.
    Currently supports:

    @todo: XXX - Add more supported string types.

    @type  ea: DWORD
    @param ea: Effective address of instruction to analyze

    @rtype:  Mixed
    @return: ASCII representation of string referenced from ea if found, None otherwise.
    '''

    # TODO: move to dump script

    dref = Dfirst(ea)
    s    = ""

    if dref == BADADDR:
        return None

    string_type = GetStringType(dref)

    if string_type == ASCSTR_C:
        while True:
            byte = Byte(dref)

            if byte == 0 or byte < 32 or byte > 126:
                break

            s    += chr(byte)
            dref += 1

    return s

####################################################################################################################
def create_instruction (ea, basic_block_id, function_id, module_id):
    '''
    Analyze the instruction at ea.

    @see: defines.py

    @type  ea:          DWORD
    @param ea:          Effective address of instruction to analyze
    @type  analysis:    Integer
    @param analysis:    (Optional, Def=ANALYSIS_NONE) Which extra analysis options to enable
    @type  basic_block: pgraph.basic_block
    @param basic_block: (Optional, Def=None) Pointer to parent basic block container
    '''

    ss = pida.sql_singleton()

    # raw instruction bytes.
    bytes = ""

    for address in xrange(ea, ItemEnd(ea)):
        temp_byte = hex(Byte(address))[2:]
        if len(temp_byte) < 2:
            temp_byte = "0" + temp_byte
        bytes += temp_byte

    sql = ss.INSERT_INSTRUCTION % (ea, basic_block_id, function_id, module_id, GetMnem(ea), bytes)

    curs.execute(sql)
    dbid = curs.lastrowid

    instruction_address_lookup[ea] = (dbid, basic_block_id, function_id)

    comment = Comment(ea)
    if comment != None:
        curs.execute(ss.UPDATE_INSTRUCTION_COMMENT % (comment.replace("'", "''"), dbid))

    # instruction mnemonic and operands.
    op1  = GetOpnd(ea, 0)
    if op1 != None and op1 != "":
        curs.execute(ss.UPDATE_INSTRUCTION_OPERAND1 % (op1.replace("'", "''"), dbid))
        op2  = GetOpnd(ea, 1)
        if op2 != None and op2 != "":
            curs.execute(ss.UPDATE_INSTRUCTION_OPERAND2 % (op2.replace("'", "''"), dbid))
            op3  = GetOpnd(ea, 2)
            if op3 != None and op3 != "":
                curs.execute(ss.UPDATE_INSTRUCTION_OPERAND3 % (op3.replace("'", "''"), dbid))


    #TODO process these last?
    # XXX - this is a dirty hack to determine if and any API reference.
    xref  = Dfirst(ea)

    flags = GetFunctionFlags(xref)
    # TODO This isn't in the schema.. do we need it?
    #curs.execute(ss.UPDATE_INSTRUCTION_FLAGS % (flags, dbid))


    if xref == BADADDR:
        xref  = get_first_cref_from(ea)
        flags = GetFunctionFlags(xref)

    if SegName(xref) == ".idata":
        name = get_name(xref, xref)

        if name and get_name_ea(BADADDR, name) != BADADDR:
            refs_api = (get_name_ea(BADADDR, name), name)

    refs_string   = get_string_reference(ea)
    refs_arg      = _get_arg_ref(ea)
    refs_constant = _get_constant_ref(ea)
    refs_var      = _get_var_ref(ea)

    return dbid

####################################################################################################################
def __init_collect_function_chunks__ (ea_start):
    '''
    Generate and return the list of function chunks (including the main one) for the current function. Ripped from
    idb2reml (Ero Carerra).

    @rtype   List
    @return: List of function chunks (start, end tuples) for the current function.
    '''

    chunks   = []
    iterator = func_tail_iterator_t(get_func(ea_start))
    status   = iterator.main()

    while status:
        chunk = iterator.chunk()
        chunks.append((chunk.startEA, chunk.endEA))
        status = iterator.next()

    return chunks

####################################################################################################################
def create_basic_block (ea_start, ea_end, depth, analysis, function_id, module_id):
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

    heads = [head for head in Heads(ea_start, ea_end + 1) if isCode(GetFlags(head))]

    sql = ss.INSERT_BASIC_BLOCK % ( ea_start, ea_end, function_id, module_id)

    curs.execute(sql)
    dbid = curs.lastrowid

    sql_connection.commit()

    ea_start         = ea_start
    ea_end           = ea_end

    if depth & DEPTH_INSTRUCTIONS:
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

#    if is_call_insn(ea):
#        return []

    xrefs = CodeRefsFrom(ea, 1)

    if ea == 0x411a2a:
        print "JJJ"
        print xrefs

    # if the only xref from ea is next ea, then return nothing.
    if len(xrefs) == 1 and xrefs[0] == NextNotTail(ea):
        xrefs = []

    for xr in xrefs:
        global_branches_from[ea] = xr
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
            #global_branches_from[xref] = ea
            global_branches[(xref, ea)] = 1

    return xrefs

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
def __init_enumerate_rpc__ (module_id):
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
                    print "PIDA.MODULE> No function node for RPC routine @%08X" % addr

                ea     += 4
                opcode += 1


####################################################################################################################
def __init_basic_blocks__ (ea_start, depth, analysis, function_id, module_id):
    '''
    Enumerate the basic block boundaries for the current function and store them in a graph structure.
    '''

    chunks = __init_collect_function_chunks__(ea_start)

    for (chunk_start, chunk_end) in chunks:
        edges       = []
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
            if is_ret_insn(ea):
                bb = create_basic_block(block_start, ea, depth, analysis, function_id, module_id)

                # start a new block at the next ea.
                block_start = next_ea

            # if there is a branch to the current instruction, end the current node at previous ea.
            elif br_to and block_start != ea:
                bb = create_basic_block(block_start, prev_ea, depth, analysis, function_id, module_id)

                # draw an "implicit" branch.
                if not is_ret_insn(prev_ea):
                    edges.append((block_start, ea, 0x0000FF))

                # start a new block at ea.
                block_start = ea

            # if there is a branch from the current instruction, end the current node at ea.
            elif br_from:
                bb = create_basic_block(block_start, ea, depth, analysis, function_id, module_id)

                # start a new block at the next ea.
                block_start = next_ea
            else:
                # TODO find a way to catch imports
                pass
####################################################################################################################
def __init_args_and_local_vars__ (func_struct, frame_struct, function_id, module_id):
    '''
    Calculate the total size of arguments, # of arguments and # of local variables. Update the internal class member
    variables appropriately.
    '''

    if not frame_struct:
        return

    ss = pida.sql_singleton()

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
            curs.execute("INSERT INTO function_variables (function, module, name, flags, offset) VALUES (%d, %d, '%s', %d, %d);" %(function_id, module_id, name.replace("'", "''"), vtype, end_offset))

    arg_size = frame_offset - argument_boundary
    curs.execute(ss.UPDATE_FUNCTION_ARG_SIZE % (arg_size, function_id))


def create_module(name, signature=None, depth=DEPTH_FULL, analysis=ANALYSIS_NONE):
    sql = ss.INSERT_MODULE % (name, MinEA() - 0x1000, "0")

    curs.execute(sql)
    module_id = curs.lastrowid

    sql_connection.commit()

    log = True

    # enumerate and add the functions within the module.
    if log:
        print "Analyzing functions..."

    for ea in Functions(MinEA(), MaxEA()):
        func = create_function(ea, depth, analysis, module_id)

    # enumerate and add nodes for each import within the module.
    if depth & DEPTH_INSTRUCTIONS and analysis & ANALYSIS_IMPORTS:
        if log:
            print"Enumerating imports..."

        enumerate_imports()

    # enumerate and propogate attributes for any discovered RPC interfaces.
    if analysis & ANALYSIS_RPC:
        if log:
            print "Enumerating RPC interfaces..."

        __init_enumerate_rpc__(module_id)

    # enumerate and add the intramodular cross references.
    if log:
        print "Enumerating intramodular cross references..."

    # TODO do data xrefs as well (this may clear up imports not being stored)

def create_function (ea_start, depth=DEPTH_FULL, analysis=ANALYSIS_NONE, module_id=0):
        ss = pida.sql_singleton()

        # The end address is the same as the start address for the insertion
        sql = ss.INSERT_FUNCTION % (module_id, ea_start, ea_start, "")

        curs.execute(sql)
        dbid = curs.lastrowid

        sql_connection.commit()

        # grab the ida function and frame structures.
        func_struct  = get_func(ea_start)
        frame_struct = get_frame(func_struct)

        # grab the function flags.
        flags = GetFunctionFlags(ea_start)
        curs.execute(ss.UPDATE_FUNCTION_FLAGS % (flags, dbid))

        #TODO should this be done first?
        # if we're not in a "real" function. set the id and ea_start manually and stop analyzing.
        if not func_struct or flags & FUNC_LIB or flags & FUNC_STATIC:
            name       = get_name(ea_start, ea_start)
            is_import  = True

            return dbid
        ######### END TODO ############

        ea_start       = func_struct.startEA
        ea_end         = PrevAddr(func_struct.endEA)
        name           = GetFunctionName(ea_start)

        curs.execute("UPDATE function SET start_address=%d, end_address=%d, name='%s' WHERE id = %d;" % (ea_start, ea_end, name.replace("'","''"), dbid))

        saved_reg_size = func_struct.frregs
        frame_size     = get_frame_size(func_struct)
        ret_size       = get_frame_retsize(func_struct)
        local_var_size = func_struct.frsize

        curs.execute("INSERT INTO frame_info (function, saved_reg_size, frame_size, ret_size, local_var_size) VALUES (%d, %d, %d, %d, %d);" % (dbid, saved_reg_size, frame_size, ret_size, local_var_size))

        chunks         = [(ea_start, ea_end)]

        __init_args_and_local_vars__(func_struct, frame_struct, dbid, module_id)

        if depth & DEPTH_BASIC_BLOCKS:
            __init_basic_blocks__(ea_start, depth, analysis, dbid, module_id)

        return dbid


sql_connection = sqlite.connect(":memory:")
ss = pida.sql_singleton()
curs = sql_connection.cursor()

# Initialize global BB edges list
global_branches_from = {}
global_branches = {}
instruction_address_lookup = {}


main()