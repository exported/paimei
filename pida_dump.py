#
# IDA Python PIDA Database Generation Script
# Dumps the current IDB into a .PIDA file.
#
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

### XREF TYPES ###
CODE_TO_CODE_FUNCTION       = 1
DATA_TO_FUNCTION            = 2
CODE_TO_CODE_BASIC_BLOCK    = 4
CODE_TO_CODE_INSTRUCTION    = 8

VAR_TYPE_ARGUMENT   = 1
VAR_TYPE_LOCAL      = 2

def main():
    depth    = None
    analysis = ANALYSIS_NONE
    
    while not depth:
        depth = DEPTH_FULL
        #depth = AskStr("full", "Depth to analyze? (full, functions|func, basic blocks|bb)")
        #
        #if depth:
        #    depth = depth.lower()
        #
        #if   depth in ["full"]:                depth = DEPTH_FULL
        #elif depth in ["functions", "func"]:   depth = DEPTH_FUNCTIONS
        #elif depth in ["basic blocks", "bb"]:  depth = DEPTH_BASIC_BLOCKS
        #else:
        #    Warning("Unsupported depth: %s\n\nValid options include:\n\t- full\n\t- functions\n\t- basic blocks" % depth)
        #    depth = None
        #
    #choice = AskYN(1, "Propogate nodes and edges for API calls (imports)?")
    choice = 1
    if choice == 1:
        analysis |= ANALYSIS_IMPORTS
    
    #choice = AskYN(1, "Enumerate RPC interfaces and dispatch routines?")
    choice = 1
    if choice == 1:
        analysis |= ANALYSIS_RPC
    
    
    #output_file = AskFile(1, GetInputFile() + ".pida", "Save PIDA file to?")
    output_file = GetInputFile() + ".pida"
    
    
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
            print "PIDA.DUMP> Could not calculate signature for %s, perhaps the file was moved?" % GetInputFilePath()
            signature = ""
    
        create_module(GetInputFile(), signature, depth, analysis)
    
        print "Saving to file...",
    
        copy_from_memory(GetInputFile())
        
        print "Done. Completed in %f seconds.\n" % round(time.time() - start, 3)
            
def copy_from_memory(filename):
    outfile = filename + ".db"

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
    
    print "closing the database"
    
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
        bytes += hex(Byte(address))[2:]

    dbid = __create_instruction(ea, basic_block_id, function_id, module_id, GetMnem(ea), bytes)

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

    refs_string   = None
    refs_arg      = _get_arg_ref(ea)
    refs_constant = _get_constant_ref(ea)
    refs_var      = _get_var_ref(ea)

    return dbid

####################################################################################################################
def __create_instruction (address, basic_block_id, function_id, module_id, mnemonic, bytes):
    sql = ss.INSERT_INSTRUCTION % (address, basic_block_id, function_id, module_id, mnemonic, bytes)

    curs.execute(sql)
    dbid = curs.lastrowid

    return dbid

####################################################################################################################
def __create_module_record(name, base, version):
    sql = ss.INSERT_MODULE % (name, base, version)

    curs.execute(sql)
    dbid = curs.lastrowid

    sql_connection.commit()

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

    dbid = __create_basic_block_record(module_id, function_id, ea_start, ea_end)

    id               = ea_start
    ea_start         = ea_start
    ea_end           = ea_end
    instructions     = {}
    ext              = {}

    if depth & DEPTH_INSTRUCTIONS:
        for ea in heads:
            instructions[ea] = create_instruction(ea, dbid, function_id, module_id)
        sql_connection.commit()

####################################################################################################################
def __create_basic_block_record(module_id, function_id, start_address, end_address):
    sql = ss.INSERT_BASIC_BLOCK % ( start_address, end_address, function_id, module_id)

    curs.execute(sql)
    dbid = curs.lastrowid

    sql_connection.commit()

    return dbid

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

    if is_call_insn(ea):
        return []

    xrefs = CodeRefsFrom(ea, 1)

    # if the only xref from ea is next ea, then return nothing.
    if len(xrefs) == 1 and xrefs[0] == NextNotTail(ea):
        xrefs = []

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
        if not is_call_insn(xref) and xref not in [prev_ea, prev_code_ea]:
            xrefs.append(xref)

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
    module_id = __create_module_record(name, MinEA() - 0x1000, "0")

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
    
    functions = curs.execute("SELECT id, start_address FROM function;").fetchall()
    
    for func in functions:
        code_xrefs_to = CodeRefsTo(func[1], 0)
        data_xrefs_to = DataRefsTo(func[1])
        
        for ref in code_xrefs_to:
            src_func = get_func(ref)
            
            if src_func:
                src_address = src_func.startEA
                
                # If it's not in a function, I guess we ignore it
                if src_address:
                    src_id = curs.execute("SELECT id FROM function WHERE start_address = %d AND module = %d;" % (src_address, module_id)).fetchone()[0]
                    
                    curs.execute("INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, %d);" % (src_id, func[0], CODE_TO_CODE_FUNCTION))                
                
        if depth & DEPTH_INSTRUCTIONS:                    
            dest = curs.execute("SELECT id FROM instruction WHERE address = %d;" % func[1]).fetchone()
            if not dest:
                print "0x%x: bad code ref dest" % func[1]
            else:
                dest_id = dest[0]
                         
                if len(code_xrefs_to) > 0:
                    for ref in code_xrefs_to:
                        src = curs.execute ("SELECT id FROM instruction WHERE address = %d;" % ref).fetchone()
                        if not src:
                            print "0x%x: bad code ref source" % ref
                        else:
                            src_id = src[0]
                    
                            curs.execute("INSERT INTO cross_references (source, destination, reference_type) VALUES (%d, %d, %d);" % (src_id, dest_id, CODE_TO_CODE_INSTRUCTION))
    

def create_function_record(module_id, start_address, end_address, name):
    ss = pida.sql_singleton()

    sql = ss.INSERT_FUNCTION % (module_id, start_address, end_address, name)

    curs.execute(sql)
    dbid = curs.lastrowid

    sql_connection.commit()
    return dbid

def create_function (ea_start, depth=DEPTH_FULL, analysis=ANALYSIS_NONE, module=0):
        ss = pida.sql_singleton()

        dbid = create_function_record(module, ea_start, ea_start, "")

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

        __init_args_and_local_vars__(func_struct, frame_struct, dbid, module)

        if depth & DEPTH_BASIC_BLOCKS:
            __init_basic_blocks__(ea_start, depth, analysis, dbid, module)
            
        return dbid






sql_connection = sqlite.connect(":memory:")
ss = pida.sql_singleton()
curs = sql_connection.cursor()
    
main()