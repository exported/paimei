#
# Bak Mei - The Pai Mei Backend
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

import struct
import binascii

from defines        import *
from sql_singleton  import *

class instruction(object):
    '''
    This class represents an assembly instruction.

    @author:       Cameron Hotchkies, Pedram Amini
    @license:      GNU General Public License 2.0 or later
    @contact:      chotchkies@tippingpoint.com
    @organization: www.openrce.org

    @cvar dbid:    Database Identifier
    @type dbid:    Integer
    @cvar DSN:     Database location
    @type DSN:     String

    @type ea:       DWORD
    @type comment:  String
    @type bytes:    List
    @type mnem:     String
    @type disasm:   String
        
    '''

    __ea            = None                      # effective address of instruction
    __comment       = ""                        # comment at instruction EA
    __bytes         = []                        # instruction raw bytes, mnemonic and operands
    __mnem          = None                      # the mnemonic of the instruction
    __operands      = None

    dbid            = None                      # Database ID
    DSN             = None
    basic_block     = None                      # parent basic_block id

    __cached        = False
    __operand_cache = False

    # TODO : remove these bad boys
    refs_string     = None                      # string, if any, that this instruction references
    refs_api        = None                      # known API, if any, that this instruction references
    refs_arg        = None                      # argument, if any, that this instruction references
    refs_constant   = None                      # constant value, if any, that this instruction references
    refs_var        = None                      # local variable, if any, that this instruction references

    ext             = {}

    ####################################################################################################################
    def __init__ (self, DSN, database_id):
        '''
        Initializes an instruction object.

        @type  database_id: Integer
        @param database_id: The id of the instruction in the database
        @type  DSN:         String
        @param DSN:         The filename for the database to read from.
        '''

        self.dbid = database_id
        self.DSN = DSN
        self.__cached = False

    ####################################################################################################################
    def __load_from_sql(self):
        ss = sql_singleton()
        results = ss.select_instruction(self.DSN, self.dbid)

        if results:
            self.__ea       = results['address']
            self.__mnem     = results['mnemonic']
            self.__comment  = results['comment']

            bytes = []

            try:

                for byte in binascii.a2b_hex(results['bytes']):
                    bytes.append(struct.unpack('B', byte)[0])
            except:
                print "Errored out on %s on address %x" % (results['bytes'], self.__ea)

            self.__bytes = bytes

            self.basic_block = results['basic_block']

            self.__cached = True
        else:
            raise "Error loading instruction [ID:%d] from database [FILE:%s]" % (self.dbid, self.DSN)

    ####################################################################################################################
    
    def __load_operands_from_sql(self):
        pass
        
        ss = sql_singleton()
        
        results = ss.select_instruction_operands(self.DSN, self.dbid)
        
        if results:
            self.__operands = []
            
            for oper in results:
                new_oper = operand(self.DSN, oper)
                self.__operands.append(new_oper)
                
        self.__operand_cache = True
    
    ####################################################################################################################
    def flag_dependency (first_instruction, second_instruction):
        '''
        Determine if one instruction can affect flags used by the other instruction.

        @type   first_instruction:  instruction
        @param  first_instruction:  The first instruction to check
        @type   second_instruction: instruction
        @param  second_instruction: The second instruction to check

        @rtype: Integer
        @return: 0 for no effect, 1 for first affects second, 2 for second affects first, 3 for both can affect
        '''

        if first_instruction.mnem in instruction.__FLAGGED_OPCODES and second_instruction.mnem in instruction.__FLAGGED_OPCODES:
            ret_val = 0

            # if neither opcodes set any flags, they can be ignored
            if instruction.__FLAGGED_OPCODES[first_instruction.mnem]  & instruction.__SET_MASK > 0 and \
               instruction.__FLAGGED_OPCODES[second_instruction.mnem] & instruction.__SET_MASK > 0:
                return 0

            setter = instruction.__FLAGGED_OPCODES[first_instruction.mnem]  & instruction.__SET_MASK
            tester = instruction.__FLAGGED_OPCODES[second_instruction.mnem] & instruction.__TEST_MASK

            if setter & (tester << 16) > 0:
                ret_val += 1

            setter = instruction.__FLAGGED_OPCODES[second_instruction.mnem] & instruction.__SET_MASK
            tester = instruction.__FLAGGED_OPCODES[first_instruction.mnem]  & instruction.__TEST_MASK

            if setter & (tester << 16) > 0:
                ret_val += 2

            return ret_val

        return 0

    ####################################################################################################################
    # ea accessors

    def __getAddress (self):
        '''
        The address of the instruction

        @rtype:  DWORD
        @return: The address of the instruction
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__ea

    ####

    def __setAddress (self, value):
        '''
        Sets the address of the instruction.

        @type  value: DWORD
        @param value: The address of the instruction.
        '''

        if self.__cached:
            self.__ea = value

        ss = sql_singleton()
        ss.update_instruction_address(self.DSN, self.dbid, value)

    ####

    def __deleteAddress (self):
        '''
        Clears the name of the module
        '''
        del self.__ea

    ####################################################################################################################
    # comment accessors

    def __getComment (self):
        '''
        The instruction comment.

        @rtype:  String
        @return: The instruction comment
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__comment

    ####

    def __setComment (self, value):
        '''
        Sets the instruction comment.

        @type  value: String
        @param value: The instruction comment.
        '''

        if self.__cached:
            self.__comment = value

        ss = sql_singleton()
        ss.update_instruction_comment(self.DSN, self.dbid, value)

    ####

    def __deleteComment (self):
        '''
        destructs the instruction comment
        '''

        del self.__comment


    ####################################################################################################################
    # bytes accessors

    def __getBytes (self):
        '''
        The raw bytes of the instruction

        @rtype:  [Integers]
        @return: The raw bytes of the instruction
        '''

        if not self.__cached:
            self.__load_from_sql()
            pass

        return self.__bytes

    ####

    def __setBytes (self, value):
        '''
        Sets the name of the module.

        @type  value: [Integer]
        @param value: The raw bytes of the instruction
        '''

        if self.__cached:
            self.__bytes = value

        bytes = ""

        for byte in value:
            temp_byte = hex(byte)[2:]
            if len(temp_byte) < 2:
                temp_byte = "0" + temp_byte
            bytes += temp_byte

        ss = sql_singleton()
        ss.update_instruction_bytes(self.DSN, self.dbid, bytes)

    ####

    def __deleteBytes (self):
        '''
        destructs the raw bytes of the instruction
        '''

        del self.__bytes


    ####################################################################################################################
    # mnem accessors

    def __getMnemonic (self):
        '''
        The instruction mnemonic.

        @rtype:  String
        @return: The instruction mnemonic
        '''

        if not self.__cached:
            self.__load_from_sql()

        return self.__mnem

    ####

    def __setMnemonic (self, value):
        '''
        Sets the instruction mnemonic.

        @type  value: String
        @param value: The instuction mnemonic.
        '''

        if self.__cached:
            self.__mnem = value

        ss = sql_singleton()
        ss.update_instruction_mnemonic(self.DSN, self.dbid, value)

    ####

    def __deleteMnemonic (self):
        '''
        destructs the instuction mnemonic
        '''

        del self.__mnem

    ####################################################################################################################
    # operands Accessors

    def __getOperands (self):
        '''
        Gets the operands for the instruction

        @rtype:  [operand]
        @return: The first operand of the instruction
        '''

        if not self.__operand_cache:
            self.__load_operands_from_sql()

        return self.__operands

    ####

    def __setOperands (self, value):
        '''
        Sets the first operand of the instruction

        @type  value: operand
        @param value: The first operand of the instruction
        '''

        raise NotImplementedError, "The operands property is read-only. Use the set_operand() method instead."

    ####

    def __deleteOperands (self):
        '''
        destructs the first operand of the instruction
        '''
        del self.__operands

    ####################################################################################################################

    def set_operand(self, position, value):
        '''
        Updates the text representation of an operand.
        
        @type  position:    Integer
        @param position:    The position of the operand in the instruction. This is zero based.
        @type  value:       String
        @param value:       The new text representation of the operand.
        '''
    
        if position < 0 or position >= len(self.operands):
            raise IndexError, "The operand to be updated does not exist."
            
        self.__operands[position].text = value
    
    ####################################################################################################################
    # xrefs_to accessors

    def __getXrefsTo (self):
        '''
        Returns the instructions that reference this instruction.

        @rtype:   [instruction]
        @returns: A list of instructions that reference this instructon
        '''

        ret_val = []

        ss = sql_singleton()

        results = ss.select_instruction_references_to(self.DSN, self.dbid)

        for instruction_id in results:
            ret_val.append(instruction(self.DSN, instruction_id))

        return ret_val

    def __setXrefsTo (self, value):

        raise NotImplementedError, "xrefs_to is a read-only property"

    def __deleteXrefsTo (self):
        # nothing to destroy
        pass

    ####################################################################################################################
    # disasm accessors

    def __getDisasm (self):
        '''
        Returns the disassembly view of the instruction.

        @rtype:   String
        @returns: The disassembly view of the instruction.
        '''

        ret_val = self.mnem

        for oper in self.operands:
            ret_val += " " + oper + ","
            
        ret_val = ret_val[:-1]

        return ret_val

    def __setDisasm (self, value):

        raise NotImplementedError, "disasm is a read-only property"

    def __deleteDisasm (self):
        # nothing to destroy
        pass


    ####################################################################################################################
    def is_conditional_branch (self):
        '''
        Check if the instruction is a conditional branch. (x86 specific)

        @rtype:  Boolean
        @return: True if the instruction is a conditional branch, False otherwise.
        '''

        if len(self.mnem) and self.mnem[0] == 'j' and self.mnem != "jmp":
            return True

        return False


    ####################################################################################################################
    def overwrites_register (self, register):
        '''
        Indicates if the given register is modified by this instruction. This does not check for all modifications,
        just lea, mov and pop into the specific register.

        @type   register: String
        @param  register: The text representation of the register

        @rtype: Boolean
        @return: True if the register is modified
        '''

        if self.mnem == "mov" or self.mnem == "pop" or self.mnem == "lea":
            if self.op1 == register:
                return True

        if self.mnem == "xor" and self.op1 == self.op2 and self.op1 == register:
            return True

        if register == "eax" and self.mnem == "call":
            return True

        return False


    ####################################################################################################################
    ### constants for flag-using instructions (ripped from bastard)
    ###

    __TEST_CARRY  =   0x0001
    __TEST_ZERO   =   0x0002
    __TEST_OFLOW  =   0x0004
    __TEST_DIR    =   0x0008
    __TEST_SIGN   =   0x0010
    __TEST_PARITY =   0x0020
    __TEST_NCARRY =   0x0100
    __TEST_NZERO  =   0x0200
    __TEST_NOFLOW =   0x0400
    __TEST_NDIR   =   0x0800
    __TEST_NSIGN  =   0x1000
    __TEST_NPARITY=   0x2000
    __TEST_SFEQOF =   0x4000
    __TEST_SFNEOF =   0x8000
    __TEST_ALL    =   __TEST_CARRY | __TEST_ZERO |  __TEST_OFLOW | __TEST_SIGN |  __TEST_PARITY

    __SET_CARRY   =   0x00010000
    __SET_ZERO    =   0x00020000
    __SET_OFLOW   =   0x00040000
    __SET_DIR     =   0x00080000
    __SET_SIGN    =   0x00100000
    __SET_PARITY  =   0x00200000
    __SET_NCARRY  =   0x01000000
    __SET_NZERO   =   0x02000000
    __SET_NOFLOW  =   0x04000000
    __SET_NDIR    =   0x08000000
    __SET_NSIGN   =   0x10000000
    __SET_NPARITY =   0x20000000
    __SET_SFEQOF  =   0x40000000
    __SET_SFNEOF  =   0x80000000
    __SET_ALL     =   __SET_CARRY | __SET_ZERO |  __SET_OFLOW | __SET_SIGN |  __SET_PARITY

    __TEST_MASK   =   0x0000FFFF
    __SET_MASK    =   0xFFFF0000


    ####################################################################################################################
    ### flag-using instructions in a dictionary (ripped from bastard)
    ###

    __FLAGGED_OPCODES = \
    {
        "add"      : __SET_ALL,
        "or"       : __SET_ALL,
        "adc"      : __TEST_CARRY | __SET_ALL,
        "sbb"      : __TEST_CARRY | __SET_ALL,
        "and"      : __SET_ALL,
        "daa"      : __TEST_CARRY | __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "sub"      : __SET_ALL,
        "das"      : __TEST_CARRY | __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "xor"      : __SET_ALL,
        "aaa"      : __SET_CARRY,
        "cmp"      : __SET_ALL,
        "aas"      : __SET_CARRY,
        "inc"      : __SET_ZERO | __SET_OFLOW | __SET_SIGN | __SET_PARITY,
        "dec"      : __SET_ZERO | __SET_OFLOW | __SET_SIGN | __SET_PARITY,
        "arpl"     : __SET_ZERO,
        "imul"     : __SET_CARRY | __SET_OFLOW,
        "jo"       : __TEST_OFLOW,
        "jno"      : __TEST_NOFLOW,
        "jbe"      : __TEST_CARRY | __TEST_ZERO,
        "ja"       : __TEST_NCARRY | __TEST_NZERO,
        "js"       : __TEST_SIGN,
        "jns"      : __TEST_NSIGN,
        "jl"       : __TEST_SFNEOF,
        "jge"      : __TEST_SFEQOF,
        "jle"      : __TEST_ZERO | __TEST_SFNEOF,
        "jg"       : __TEST_NZERO | __TEST_SFEQOF,
        "test"     : __SET_ALL,
        "sahf"     : __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "into"     : __TEST_OFLOW,
        "iret"     : __SET_ALL,
        "aam"      : __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "aad"      : __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "cmc"      : __SET_CARRY,
        "clc"      : __SET_NCARRY,
        "stc"      : __SET_CARRY,
        "cld"      : __SET_NDIR,
        "std"      : __SET_DIR,
        "lsl"      : __SET_ZERO,
        "ucomiss"  : __SET_ALL,
        "comiss"   : __SET_ALL,
        "cmovo"    : __TEST_OFLOW,
        "cmovno"   : __TEST_NOFLOW,
        "cmovbe"   : __TEST_CARRY | __TEST_ZERO,
        "cmova"    : __TEST_NCARRY | __TEST_NZERO,
        "cmovs"    : __TEST_SIGN,
        "cmovns"   : __TEST_NSIGN,
        "cmovl"    : __TEST_OFLOW | __TEST_SIGN,
        "cmovge"   : __TEST_OFLOW | __TEST_SIGN,
        "cmovle"   : __TEST_ZERO | __TEST_OFLOW | __TEST_SIGN,
        "cmovg"    : __TEST_OFLOW | __TEST_SIGN | __TEST_NZERO,
        "seto"     : __TEST_OFLOW,
        "setno"    : __TEST_OFLOW,
        "setbe"    : __TEST_CARRY | __TEST_ZERO,
        "seta"     : __TEST_CARRY | __TEST_ZERO,
        "sets"     : __TEST_SIGN,
        "setns"    : __TEST_SIGN,
        "setl"     : __TEST_OFLOW | __TEST_SIGN,
        "setge"    : __TEST_OFLOW | __TEST_SIGN,
        "setle"    : __TEST_ZERO | __TEST_OFLOW | __TEST_SIGN,
        "setg"     : __TEST_ZERO | __TEST_OFLOW | __TEST_SIGN,
        "bt"       : __SET_CARRY,
        "shld"     : __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "rsm"      : __SET_ALL,
        "bts"      : __SET_CARRY,
        "shrd"     : __SET_CARRY | __SET_ZERO | __SET_SIGN | __SET_PARITY,
        "cmpxchg"  : __SET_ALL,
        "btr"      : __SET_CARRY,
        "btc"      : __SET_CARRY,
        "bsf"      : __SET_ZERO,
        "bsr"      : __SET_ZERO,
        "xadd"     : __SET_ALL,
        "verr"     : __SET_ZERO,
        "verw"     : __SET_ZERO,
        "rol"      : __SET_CARRY | __SET_OFLOW,
        "ror"      : __SET_CARRY | __SET_OFLOW,
        "rcl"      : __TEST_CARRY | __SET_CARRY | __SET_OFLOW,
        "rcr"      : __TEST_CARRY | __SET_CARRY | __SET_OFLOW,
        "shl"      : __SET_ALL,
        "shr"      : __SET_ALL,
        "sal"      : __SET_ALL,
        "sar"      : __SET_ALL,
        "neg"      : __SET_ALL,
        "mul"      : __SET_CARRY | __SET_OFLOW,
        "fcom"     : __SET_CARRY | __SET_ZERO | __SET_PARITY,
        "fcomp"    : __SET_CARRY | __SET_ZERO | __SET_PARITY,
        "fcomp"    : __TEST_CARRY | __SET_CARRY | __SET_PARITY,
        "fcmovb"   : __TEST_CARRY,
        "fcmove"   : __TEST_ZERO,
        "fcmovbe"  : __TEST_CARRY | __TEST_ZERO,
        "fcmovu"   : __TEST_PARITY,
        "fcmovnb"  : __TEST_NCARRY,
        "fcmovne"  : __TEST_NZERO,
        "fcmovnbe" : __TEST_NCARRY | __TEST_NZERO,
        "fcmovnu"  : __TEST_NPARITY,
        "fcomi"    : __SET_CARRY | __SET_ZERO | __SET_PARITY,
        "fcomip"   : __SET_CARRY | __SET_ZERO | __SET_PARITY
    }

    ####################################################################################################################
    # PROPERTIES
    ea          = property(__getAddress,    __setAddress,   __deleteAddress,    "The address of the instruction.")
    comment     = property(__getComment,    __setComment,   __deleteComment,    "The instruction comment.")
    bytes       = property(__getBytes,      __setBytes,     __deleteBytes,      "The raw bytes of the instruction.")
    mnem        = property(__getMnemonic,   __setMnemonic,  __deleteMnemonic,   "The instruction mnemonic.")
    operands    = property(__getOperands,   __setOperands,  __deleteOperands,   "The list of operands. (read-only)")
    disasm      = property(__getDisasm,     __setDisasm,    __deleteDisasm,     "The textual disassembly of the instruction.")
    xrefs_to    = property(__getXrefsTo,    __setXrefsTo,   __deleteXrefsTo,    "The instructions that referenc this instruction.")
    id          = property(__getAddress,    __setAddress,   __deleteAddress,    "The identifier for the class (internal use only).")