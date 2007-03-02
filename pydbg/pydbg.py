#!c:\python\python.exe

#
# PyDBG
# Copyright (C) 2006 Pedram Amini <pedram.amini@gmail.com>
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

'''
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

import sys
import pydasm
import struct

from my_ctypes import *
from defines   import *
from windows_h import *

# macos compatability.
try:
    kernel32 = windll.kernel32
except:
    kernel32 = CDLL("libmacdll.dylib")

from breakpoint              import *
from hardware_breakpoint     import *
from memory_breakpoint       import *
from memory_snapshot_block   import *
from memory_snapshot_context import *
from pdx                     import *
from pydbg_core              import *
from system_dll              import *

class pydbg(pydbg_core):
    '''
    Extending from the core this class defines a more usable debugger objects implementing a number of features such as:

        - Register manipulation.
        - Soft (INT 3) breakpoints.
        - Memory breakpoints (page permissions).
        - Hardware breakpoints.
        - Exception / event handling call backs.
        - Pydasm (libdasm) disassembly wrapper.
        - Process memory snapshotting and restoring.
        - Endian manipulation routines.
        - Debugger hiding.
        - Function resolution.
        - "Intelligent" memory derefencing.
        - Stack/SEH unwinding.
        - Etc...
    '''

    STRING_EXPLORATON_BUF_SIZE    = 256
    STRING_EXPLORATION_MIN_LENGTH = 2

    # private variables, internal use only:
    _restore_breakpoint      = None      # breakpoint to restore
    _guarded_pages           = set()     # specific pages we set PAGE_GUARD
    _guards_active           = True      # flag specifying whether or not guard pages are active

    breakpoints              = {}        # internal breakpoint dictionary, keyed by address
    memory_breakpoints       = {}        # internal memory breakpoint dictionary, keyed by base address
    hardware_breakpoints     = {}        # internal hardware breakpoint array, indexed by slot (0-3 inclusive)
    memory_snapshot_blocks   = []        # list of memory blocks at time of memory snapshot
    memory_snapshot_contexts = []        # list of threads contexts at time of memory snapshot

    first_breakpoint         = True      # this flag gets disabled once the windows initial break is handled
    memory_breakpoint_hit    = 0         # address of hit memory breakpoint or zero on miss
                                         # designates whether or not the violation was in reaction to a memory
                                         # breakpoint hit or other unrelated event.
    hardware_breakpoint_hit  = None      # hardware breakpoint on hit or None on miss
                                         # designates whether or not the single steop event was in reaction to
                                         # a hardware breakpoint hit or other unreleated event.

    instruction              = None      # pydasm instruction object, propagated by self.disasm()
    mnemonic                 = None      # pydasm decoded instruction mnemonic, propagated by self.disasm()
    op1                      = None      # pydasm decoded 1st operand, propagated by self.disasm()
    op2                      = None      # pydasm decoded 2nd operand, propagated by self.disasm()
    op3                      = None      # pydasm decoded 3rd operand, propagated by self.disasm()

    ####################################################################################################################
    def __init__ (self, ff=True, cs=False):
        '''
        Set the default attributes. See the source if you want to modify the default creation values.

        @type  ff: Boolean
        @param ff: (Optional, Def=True) Flag controlling whether or not pydbg attaches to forked processes
        @type  cs: Boolean
        @param cs: (Optional, Def=False) Flag controlling whether or not pydbg is in client/server (socket) mode
        '''

        # private variables, internal use only:
        self._restore_breakpoint      = None      # breakpoint to restore
        self._guarded_pages           = set()     # specific pages we set PAGE_GUARD on
        self._guards_active           = True      # flag specifying whether or not guard pages are active

        self.breakpoints              = {}        # internal breakpoint dictionary, keyed by address
        self.memory_breakpoints       = {}        # internal memory breakpoint dictionary, keyed by base address
        self.hardware_breakpoints     = {}        # internal hardware breakpoint array, indexed by slot (0-3 inclusive)
        self.memory_snapshot_blocks   = []        # list of memory blocks at time of memory snapshot
        self.memory_snapshot_contexts = []        # list of threads contexts at time of memory snapshot

        self.first_breakpoint         = True      # this flag gets disabled once the windows initial break is handled
        self.memory_breakpoint_hit    = 0         # address of hit memory breakpoint or zero on miss
                                                  # designates whether or not the violation was in reaction to a memory
                                                  # breakpoint hit or other unrelated event.
        self.hardware_breakpoint_hit  = None      # hardware breakpoint on hit or None on miss
                                                  # designates whether or not the single step event was in reaction to
                                                  # a hardware breakpoint hit or other unrelated event.

        self.instruction              = None      # pydasm instruction object, propagated by self.disasm()
        self.mnemonic                 = None      # pydasm decoded instruction mnemonic, propagated by self.disasm()
        self.op1                      = None      # pydasm decoded 1st operand, propagated by self.disasm()
        self.op2                      = None      # pydasm decoded 2nd operand, propagated by self.disasm()
        self.op3                      = None      # pydasm decoded 3rd operand, propagated by self.disasm()

        # control debug/error logging.
        self.pydbg_log = lambda msg: None
        self.pydbg_err = lambda msg: sys.stderr.write("PDBG_ERR> " + msg + "\n")

        # run the core's initialization routine.
        #super(pydbg, self).__init__()
        pydbg_core.__init__(self, ff=ff, cs=cs)


    ####################################################################################################################
    def bp_del (self, address):
        '''
        Removes the breakpoint from target address.

        @see: bp_set(), bp_del_all(), bp_is_ours()

        @type  address: DWORD or List
        @param address: Address or list of addresses to remove breakpoint from

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # if a list of addresses to remove breakpoints from was supplied.
        if type(address) is list:
            # pass each lone address to ourself.
            for addr in address:
                self.bp_del(addr)

            return self.ret_self()

        self.pydbg_log("bp_del(0x%08x)" % address)

        # ensure a breakpoint exists at the target address.
        if self.breakpoints.has_key(address):
            # restore the original byte.
            self.write_process_memory(address, self.breakpoints[address].original_byte)
            self.set_attr("dirty", True)

            # remove the breakpoint from the internal list.
            del self.breakpoints[address]

        return self.ret_self()


    ####################################################################################################################
    def bp_del_all (self):
        '''
        Removes all breakpoints from the debuggee.

        @see: bp_set(), bp_del(), bp_is_ours()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("bp_del_all()")

        for bp in self.breakpoints:
            self.bp_del(bp)

        return self.ret_self()


    ####################################################################################################################
    def bp_del_hw (self, address=None, slot=None):
        '''
        Removes the hardware breakpoint from the specified address or slot. Either an address or a slot must be
        specified, but not both.

        @todo: Should probably consider moving this into pydbg_core.
        @see:  bp_set_hw()

        @type  address:   DWORD
        @param address:   (Optional) Address to remove hardware breakpoint from.
        @type  slot:      Integer (0 through 3)
        @param slot:      (Optional)

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        if address == slot == None:
            raise pdx("hw bp address or slot # must be specified.")

        if not address and slot not in xrange(4):
            raise pdx("invalid hw bp slot: %d. valid range is 0 through 3" % slot)

        # ensure we have an up to date context for the current thread.
        context = self.get_thread_context(self.h_thread)

        #print "bp_del_hw() ----->"
        #print "Dr0 = %08x" % context.Dr0
        #print "Dr1 = %08x" % context.Dr1
        #print "Dr2 = %08x" % context.Dr2
        #print "Dr3 = %08x" % context.Dr3
        #print "Dr7 = %s"   % self.to_binary(context.Dr7)
        #print "      10987654321098765432109876543210"
        #print "      332222222222111111111"

        if address:
            if   context.Dr0 == address: slot = 0
            elif context.Dr1 == address: slot = 1
            elif context.Dr2 == address: slot = 2
            elif context.Dr3 == address: slot = 3

        # mark slot as inactive.
        # bits 0, 2, 4, 6 for local  (L0 - L3)
        # bits 1, 3, 5, 7 for global (L0 - L3)

        context.Dr7 &= ~(1 << (slot * 2))

        # remove address from the specified slot.
        if   slot == 0: context.Dr0 = 0x00000000
        elif slot == 1: context.Dr1 = 0x00000000
        elif slot == 2: context.Dr2 = 0x00000000
        elif slot == 3: context.Dr3 = 0x00000000

        # remove the condition (RW0 - RW3) field from the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
        context.Dr7 &= ~(3 << ((slot * 4) + 16))

        # remove the length (LEN0-LEN3) field from the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
        context.Dr7 &= ~(3 << ((slot * 4) + 18))

        # set the thread context.
        self.set_thread_context(context)

        #context = self.get_thread_context(self.h_thread)
        #print "Dr0 = %08x" % context.Dr0
        #print "Dr1 = %08x" % context.Dr1
        #print "Dr2 = %08x" % context.Dr2
        #print "Dr3 = %08x" % context.Dr3
        #print "Dr7 = %s"   % self.to_binary(context.Dr7)
        #print "      10987654321098765432109876543210"
        #print "      332222222222111111111"
        #print "<-------- bp_del_hw()"

        # remove the breakpoint from the internal list.
        del self.hardware_breakpoints[slot]

        return self.ret_self()


    ####################################################################################################################
    def bp_del_mem (self, address):
        '''
        Removes the memory breakpoint from target address.

        @see: bp_del_mem_all(), bp_set_mem(), bp_is_ours_mem()

        @type  address: DWORD
        @param address: Address or list of addresses to remove memory breakpoint from

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("bp_del_mem(0x%08x)" % address)

        # ensure a memory breakpoint exists at the target address.
        if self.memory_breakpoints.has_key(address):
            size = self.memory_breakpoints[address].size
            mbi  = self.memory_breakpoints[address].mbi

            # remove the memory breakpoint from our internal list.
            del self.memory_breakpoints[address]

            # page-aligned target memory range.
            start = mbi.BaseAddress
            end   = address + size                                  # non page-aligned range end
            end   = end + self.page_size - (end % self.page_size)   # page-aligned range end

            # for each page in the target range, restore the original page permissions if no other breakpoint exists.
            for page in range(start, end, self.page_size):
                other_bp_found = False

                for mem_bp in self.memory_breakpoints.values():
                    if page <= mem_bp.address < page + self.page_size:
                        other_bp_found = True
                        break
                    if page <= mem_bp.address + size < page + self.page_size:
                        other_bp_found = True
                        break

                if not other_bp_found:
                    try:
                        self.virtual_protect(page, 1, mbi.Protect & ~PAGE_GUARD)

                        # remove the page from the set of tracked GUARD pages.
                        self._guarded_pages.remove(mbi.BaseAddress)
                    except:
                        pass

        return self.ret_self()


    ####################################################################################################################
    def bp_del_mem_all (self):
        '''
        Removes all memory breakpoints from the debuggee.

        @see: bp_del_mem(), bp_set_mem(), bp_is_ours_mem()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("bp_del_mem_all()")

        for address in self.memory_breakpoints.keys():
            self.bp_del_mem(address)

        return self.ret_self()


    ####################################################################################################################
    def bp_is_ours (self, address_to_check):
        '''
        Determine if a breakpoint address belongs to us.

        @see: bp_set(), bp_del(), bp_del_all()

        @type  address_to_check: DWORD
        @param address_to_check: Address to check if we have set a breakpoint at

        @rtype:  Bool
        @return: True if breakpoint in question is ours, False otherwise
        '''

        if self.breakpoints.has_key(address_to_check):
            return True

        return False


    ####################################################################################################################
    def bp_is_ours_mem (self, address_to_check):
        '''
        Determines if the specified address falls within the range of one of our memory breakpoints. When handling
        potential memory breakpoint exceptions it is mandatory to check the offending address with this routine as
        memory breakpoints are implemented by changing page permissions and the referenced address may very well exist
        within the same page as a memory breakpoint but not within the actual range of the buffer we wish to break on.

        @see: bp_set_mem(), bp_del_mem(), bp_del_mem_all()

        @type  address_to_check: DWORD
        @param address_to_check: Address to check if we have set a breakpoint on

        @rtype:  Mixed
        @return: The starting address of the buffer our breakpoint triggered on or False if address falls outside range.
        '''

        for address in self.memory_breakpoints:
            size = self.memory_breakpoints[address].size

            if address_to_check >= address and address_to_check <= address + size:
                return address

        return False


    ####################################################################################################################
    def bp_set (self, address, description="", restore=True, handler=None):
        '''
        Sets a breakpoint at the designated address. Register an EXCEPTION_BREAKPOINT callback handler to catch
        breakpoint events. If a list of addresses is submitted to this routine then the entire list of new breakpoints
        get the same description and restore. The optional "handler" parameter can be used to identify a function to
        specifically handle the specified bp, as opposed to the generic bp callback handler. The prototype of the
        callback routines is::

            func (pydbg)
                return DBG_CONTINUE     # or other continue status

        @see: bp_is_ours(), bp_del(), bp_del_all()

        @type  address:     DWORD or List
        @param address:     Address or list of addresses to set breakpoint at
        @type  description: String
        @param description: (Optional) Description to associate with this breakpoint
        @type  restore:     Bool
        @param restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # if a list of addresses to set breakpoints on from was supplied
        if type(address) is list:
            # pass each lone address to ourself (each one gets the same description / restore flag).
            for addr in address:
                self.bp_set(addr, description, restore, handler)

            return self.ret_self()

        self.pydbg_log("bp_set(0x%08x)" % address)

        # ensure a breakpoint doesn't already exist at the target address.
        if not self.breakpoints.has_key(address):
            try:
                # save the original byte at the requested breakpoint address.
                original_byte = self.read_process_memory(address, 1)

                # write an int3 into the target process space.
                self.write_process_memory(address, "\xCC")
                self.set_attr("dirty", True)

                # add the breakpoint to the internal list.
                self.breakpoints[address] = breakpoint(address, original_byte, description, restore, handler)
            except:
                raise pdx("Failed setting breakpoint at %08x" % address)

        return self.ret_self()


    ####################################################################################################################
    def bp_set_hw (self, address, length, condition, description="", restore=True, handler=None):
        '''
        Sets a hardware breakpoint at the designated address. Register an EXCEPTION_SINGLE_STEP callback handler to
        catch hardware breakpoint events. Setting hardware breakpoints requires the internal h_thread handle be set.
        This means that you can not set one outside the context of an debug event handler. If you want to set a hardware
        breakpoint as soon as you attach to or load a process, do so in the first chance breakpoint handler.

        For more information regarding the Intel x86 debug registers and hardware breakpoints see::

            http://pdos.csail.mit.edu/6.828/2005/readings/ia32/IA32-3.pdf
            Section 15.2

        Alternatively, you can register a custom handler to handle hits on the specific hw breakpoint slot.

        @see:  bp_del_hw()

        @type  address:     DWORD
        @param address:     Address to set hardware breakpoint at
        @type  length:      Integer (1, 2 or 4)
        @param length:      Size of hardware breakpoint in bytes (byte, word or dword)
        @type  condition:   Integer (HW_ACCESS, HW_WRITE, HW_EXECUTE)
        @param condition:   Condition to set the hardware breakpoint to activate on
        @type  description: String
        @param description: (Optional) Description of breakpoint
        @type  restore:     Boolean
        @param restore:     (Optional, def=True) Flag controlling whether or not to restore the breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("bp_set_hw(%08x, %d, %s)" % (address, length, condition))

        # instantiate a new hardware breakpoint object for the new bp to create.
        hw_bp = hardware_breakpoint(address, length, condition, description, restore, handler=handler)

        # ensure we have an up to date context for the current thread.
        context = self.get_thread_context(self.h_thread)

        #print "bp_set_hw() ---------->"
        #print "eip = %08x" % context.Eip
        #print "Dr0 = %08x" % context.Dr0
        #print "Dr1 = %08x" % context.Dr1
        #print "Dr2 = %08x" % context.Dr2
        #print "Dr3 = %08x" % context.Dr3
        #print "Dr7 = %s"   % self.to_binary(context.Dr7)
        #print "      10987654321098765432109876543210"
        #print "      332222222222111111111"

        if length not in (1, 2, 4):
            raise pdx("invalid hw breakpoint length: %d." % length)

        # length -= 1 because the following codes are used for determining length:
        #       00 - 1 byte length
        #       01 - 2 byte length
        #       10 - undefined
        #       11 - 4 byte length
        length -= 1

        # condition table:
        #       00 - break on instruction execution only
        #       01 - break on data writes only
        #       10 - undefined
        #       11 - break on data reads or writes but not instruction fetches
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            raise pdx("invalid hw breakpoint condition: %d" % condition)

        # check for any available hardware breakpoint slots. there doesn't appear to be any difference between local
        # and global as far as we are concerned on windows.
        # bits 0, 2, 4, 6 for local  (L0 - L3)
        # bits 1, 3, 5, 7 for global (G0 - G3)

        available = None
        for slot in xrange(4):
            if context.Dr7 & (1 << (slot * 2)) == 0:
                available = slot
                break

        if available == None:
            raise pdx("no hw breakpoint slots available.")

        # mark available debug register as active (L0 - L3).
        context.Dr7 |= 1 << (available * 2)

        # save our breakpoint address to the available hw bp slot.
        if   available == 0: context.Dr0 = address
        elif available == 1: context.Dr1 = address
        elif available == 2: context.Dr2 = address
        elif available == 3: context.Dr3 = address

        # set the condition (RW0 - RW3) field for the appropriate slot (bits 16/17, 20/21, 24,25, 28/29)
        context.Dr7 |= condition << ((available * 4) + 16)

        # set the length (LEN0-LEN3) field for the appropriate slot (bits 18/19, 22/23, 26/27, 30/31)
        context.Dr7 |= length << ((available * 4) + 18)

        # set the thread context.
        self.set_thread_context(context)

        context = self.get_thread_context(self.h_thread)
        #print "Dr0 = %08x" % context.Dr0
        #print "Dr1 = %08x" % context.Dr1
        #print "Dr2 = %08x" % context.Dr2
        #print "Dr3 = %08x" % context.Dr3
        #print "Dr7 = %s"   % self.to_binary(context.Dr7)
        #print "      10987654321098765432109876543210"
        #print "      332222222222111111111"
        #print "<---------- bp_set_hw()"

        # update the internal hardware breakpoint array at the used slot index.
        hw_bp.slot = available
        self.hardware_breakpoints[available] = hw_bp

        return self.ret_self()


    ####################################################################################################################
    def bp_set_mem (self, address, size, description="", handler=None):
        '''
        Sets a memory breakpoint at the target address. This is implemented by changing the permissions of the page
        containing the address to PAGE_GUARD. To catch memory breakpoints you have to register the EXCEPTION_GUARD_PAGE
        callback. Within the callback handler check the internal pydbg variable self.memory_breakpoint_hit to
        determine if the violation was a result of a direct memory breakpoint hit or some unrelated event.
        Alternatively, you can register a custom handler to handle the memory breakpoint. Memory breakpoints are
        automatically restored via the internal single step handler. To remove a memory breakpoint, you must explicitly
        call bp_del_mem().

        @see: bp_is_ours_mem(), bp_del_mem(), bp_del_mem_all()

        @type  address:     DWORD
        @param address:     Starting address of the buffer to break on
        @type  size:        Integer
        @param size:        Size of the buffer to break on
        @type  description: String
        @param description: (Optional) Description to associate with this breakpoint
        @type  handler:     Function Pointer
        @param handler:     (Optional, def=None) Optional handler to call for this bp instead of the default handler

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("bp_set_mem() buffer range is %08x - %08x" % (address, address + size))

        # ensure the target address doesn't already sit in a memory breakpoint range:
        if self.bp_is_ours_mem(address):
            self.pydbg_log("a memory breakpoint spanning %08x already exists" % address)
            return self.ret_self()

        # determine the base address of the page containing the starting point of our buffer.
        try:
            mbi = self.virtual_query(address)
        except:
            raise pdx("bp_set_mem(): failed querying address: %08x" % address)

        self.pydbg_log("buffer starting at %08x sits on page starting at %08x" % (address, mbi.BaseAddress))

        # individually change the page permissions for each page our buffer spans.
        # why do we individually set the page permissions of each page as opposed to a range of pages? because empirical
        # testing shows that when you set a PAGE_GUARD on a range of pages, if any of those pages are accessed, then
        # the PAGE_GUARD attribute is dropped for the entire range of pages that was originally modified. this is
        # undesirable for our purposes when it comes to the ease of restoring hit memory breakpoints.
        current_page = mbi.BaseAddress

        while current_page <= address + size:
            self.pydbg_log("changing page permissions on %08x" % current_page)

            # keep track of explicitly guarded pages, to differentiate from pages guarded by the debuggee / OS.
            self._guarded_pages.add(current_page)
            self.virtual_protect(current_page, 1, mbi.Protect | PAGE_GUARD)

            current_page += self.page_size

        # add the breakpoint to the internal list.
        self.memory_breakpoints[address] = memory_breakpoint(address, size, mbi, description, handler)

        return self.ret_self()


    ####################################################################################################################
    def cleanup (self):
        '''
        Clean up after ourselves by removing all breakpoints.

        @rtype:     pydbg
        @return:    Self
        '''

        soft_breakpoints   = []
        memory_breakpoints = []

        self.pydbg_log("pydbg cleaning up")

        # create a list of all soft breakpoints.
        for address in self.breakpoints:
            soft_breakpoints.append(address)

        # create a list of all memory breakpoints.
        for address in self.memory_breakpoints:
            memory_breakpoints.append(address)

        # remove all soft breakpoints.
        for address in soft_breakpoints:
            self.bp_del(address)

        # remove all memory breakpoints.
        for address in memory_breakpoints:
            self.bp_del_mem(address)

        # run the core's cleanup routine.
        #super(pydbg, self).cleanup()
        pydbg_core.cleanup(self)

        return self.ret_self()


    ####################################################################################################################
    def dbg_print_all_guarded_pages (self):
        '''
        *** DEBUG ROUTINE ***

        This is a debugging routine that was used when debugging memory breakpoints. It was too useful to be removed
        from the release code.
        '''

        cursor = 0

        # scan through the entire memory range.
        while cursor < 0xFFFFFFFF:
            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            if mbi.Protect & PAGE_GUARD:
                address = mbi.BaseAddress
                print "PAGE GUARD on %08x" % mbi.BaseAddress

                while 1:
                    address += self.page_size
                    tmp_mbi  = self.virtual_query(address)

                    if not tmp_mbi.Protect & PAGE_GUARD:
                        break

                    print "PAGE GUARD on %08x" % address

            cursor += mbi.RegionSize


    ####################################################################################################################
    def disasm (self, address):
        '''
        Pydasm disassemble utility function wrapper. Stores the pydasm decoded instruction in self.instruction.

        @type  address: DWORD
        @param address: Address to disassemble at

        @rtype:  String
        @return: Disassembled string.
        '''

        try:
            data  = self.read_process_memory(address, 32)
        except:
            return "Unable to disassemble at %08x" % address

        # update our internal member variables.
        self.instruction = pydasm.get_instruction(data, pydasm.MODE_32)

        if not self.instruction:
            self.mnemonic = "[UNKNOWN]"
            self.op1      = ""
            self.op2      = ""
            self.op3      = ""

            return "[UNKNOWN]"
        else:
            self.mnemonic = pydasm.get_mnemonic_string(self.instruction, pydasm.FORMAT_INTEL)
            self.op1      = pydasm.get_operand_string(self.instruction, 0, pydasm.FORMAT_INTEL, address)
            self.op2      = pydasm.get_operand_string(self.instruction, 1, pydasm.FORMAT_INTEL, address)
            self.op3      = pydasm.get_operand_string(self.instruction, 2, pydasm.FORMAT_INTEL, address)

            # the rstrip() is for removing extraneous trailing whitespace that libdasm sometimes leaves.
            return pydasm.get_instruction_string(self.instruction, pydasm.FORMAT_INTEL, address).rstrip(" ")


    ####################################################################################################################
    def disasm_around (self, address, num_inst=5):
        '''
        Given a specified address this routine will return the list of 5 instructions before and after the instruction
        at address (including the instruction at address, so 11 instructions in total). This is accomplished by grabbing
        a larger chunk of data around the address than what is predicted as necessary and then disassembling forward.
        If during the forward disassembly the requested address lines up with the start of an instruction, then the
        assumption is made that the forward disassembly self corrected itself and the instruction set is returned. If
        we are unable to align with the original address, then we modify our data slice and try again until we do.

        @type  address:  DWORD
        @param address:  Address to disassemble around
        @type  num_inst: Integer
        @param num_inst: (Optional, Def=5) Number of instructions to disassemble up/down from address

        @rtype:  List
        @return: List of tuples (address, disassembly) of instructions around the specified address.
        '''

        # grab a safe window size of bytes.
        window_size = (num_inst / 5) * 64

        # grab a window of bytes before and after the requested address.
        try:
            data = self.read_process_memory(address - window_size, window_size * 2)
        except:
            return [(address, "Unable to disassemble")]

        # the rstrip() is for removing extraneous trailing whitespace that libdasm sometimes leaves.
        i           = pydasm.get_instruction(data[window_size:], pydasm.MODE_32)
        disassembly = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, address).rstrip(" ")
        complete    = False
        start_byte  = 0

        # loop until we retrieve a set of instructions that align to the requested address.
        while not complete:
            instructions = []
            slice        = data[start_byte:]
            offset       = 0

            # step through the bytes in the data slice.
            while offset < len(slice):
                i = pydasm.get_instruction(slice[offset:], pydasm.MODE_32)

                if not i:
                    break

                # calculate the actual address of the instruction at the current offset and grab the disassembly
                addr = address - window_size + start_byte + offset
                inst = pydasm.get_instruction_string(i, pydasm.FORMAT_INTEL, addr).rstrip(" ")

                # add the address / instruction pair to our list of tuples.
                instructions.append((addr, inst))

                # increment the offset into the data slice by the length of the current instruction.
                offset += i.length

            # we're done processing a data slice.
            # step through each addres / instruction tuple in our instruction list looking for an instruction alignment
            # match. we do the match on address and the original disassembled instruction.
            index_of_address = 0
            for (addr, inst) in instructions:
                if addr == address and inst == disassembly:
                    complete = True
                    break

                index_of_address += 1

            start_byte += 1

        return instructions[index_of_address-num_inst:index_of_address+num_inst+1]


    ####################################################################################################################
    def dump_context (self, context=None, stack_depth=5, print_dots=True):
        '''
        Return an informational block of text describing the CPU context of the current thread. Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @see: dump_context_list()

        @type  context:     Context
        @param context:     (Optional) Current thread context to examine
        @type  stack_depth: Integer
        @param stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @type  print_dots:  Bool
        @param print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: Information about current thread context.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = self.dump_context_list(context, stack_depth, print_dots)

        context_dump  = "CONTEXT DUMP\n"
        context_dump += "  EIP: %08x %s\n" % (context.Eip, context_list["eip"])
        context_dump += "  EAX: %08x (%10d) -> %s\n" % (context.Eax, context.Eax, context_list["eax"])
        context_dump += "  EBX: %08x (%10d) -> %s\n" % (context.Ebx, context.Ebx, context_list["ebx"])
        context_dump += "  ECX: %08x (%10d) -> %s\n" % (context.Ecx, context.Ecx, context_list["ecx"])
        context_dump += "  EDX: %08x (%10d) -> %s\n" % (context.Edx, context.Edx, context_list["edx"])
        context_dump += "  EDI: %08x (%10d) -> %s\n" % (context.Edi, context.Edi, context_list["edi"])
        context_dump += "  ESI: %08x (%10d) -> %s\n" % (context.Esi, context.Esi, context_list["esi"])
        context_dump += "  EBP: %08x (%10d) -> %s\n" % (context.Ebp, context.Ebp, context_list["ebp"])
        context_dump += "  ESP: %08x (%10d) -> %s\n" % (context.Esp, context.Esp, context_list["esp"])

        for offset in xrange(0, stack_depth + 1):
            context_dump += "  +%02x: %08x (%10d) -> %s\n" %    \
            (                                                   \
                offset * 4,                                     \
                context_list["esp+%02x"%(offset*4)]["value"],   \
                context_list["esp+%02x"%(offset*4)]["value"],   \
                context_list["esp+%02x"%(offset*4)]["desc"]     \
            )

        return context_dump


    ####################################################################################################################
    def dump_context_list (self, context=None, stack_depth=5, print_dots=True, hex_dump=False):
        '''
        Return an informational list of items describing the CPU context of the current thread. Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @see: dump_context()

        @type  context:     Context
        @param context:     (Optional) Current thread context to examine
        @type  stack_depth: Integer
        @param stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @type  print_dots:  Bool
        @param print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  Dictionary
        @return: Dictionary of information about current thread context.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = {}

        context_list["eip"] = self.disasm(context.Eip)
        context_list["eax"] = self.smart_dereference(context.Eax, print_dots, hex_dump)
        context_list["ebx"] = self.smart_dereference(context.Ebx, print_dots, hex_dump)
        context_list["ecx"] = self.smart_dereference(context.Ecx, print_dots, hex_dump)
        context_list["edx"] = self.smart_dereference(context.Edx, print_dots, hex_dump)
        context_list["edi"] = self.smart_dereference(context.Edi, print_dots, hex_dump)
        context_list["esi"] = self.smart_dereference(context.Esi, print_dots, hex_dump)
        context_list["ebp"] = self.smart_dereference(context.Ebp, print_dots, hex_dump)
        context_list["esp"] = self.smart_dereference(context.Esp, print_dots, hex_dump)

        for offset in xrange(0, stack_depth + 1):
            try:
                esp = self.flip_endian_dword(self.read_process_memory(context.Esp + offset * 4, 4))

                context_list["esp+%02x"%(offset*4)]          = {}
                context_list["esp+%02x"%(offset*4)]["value"] = esp
                context_list["esp+%02x"%(offset*4)]["desc"]  = self.smart_dereference(esp, print_dots, hex_dump)
            except:
                context_list["esp+%02x"%(offset*4)]          = {}
                context_list["esp+%02x"%(offset*4)]["value"] = 0
                context_list["esp+%02x"%(offset*4)]["desc"]  = "[INVALID]"

        return context_list


    ####################################################################################################################
    def event_handler_create_process (self):
        '''
        This is the default CREATE_PROCESS_DEBUG_EVENT handler. Calls through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        if not self.follow_forks:
            return DBG_CONTINUE

        h_process = self.dbg.u.CreateProcessInfo.hProcess
        h_thread  = self.dbg.u.CreateProcessInfo.hThread
        core_ret  = pydbg_core.event_handler_create_process(self)

        if self.callbacks.has_key(CREATE_PROCESS_DEBUG_EVENT):
            return self.callbacks[CREATE_PROCESS_DEBUG_EVENT](self)
        else:
            return core_ret


    ####################################################################################################################
    def event_handler_create_thread (self):
        '''
        This is the default CREATE_THREAD_DEBUG_EVENT handler. Calls through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        core_ret = pydbg_core.event_handler_create_thread(self)

        if self.callbacks.has_key(CREATE_THREAD_DEBUG_EVENT):
            return self.callbacks[CREATE_THREAD_DEBUG_EVENT](self)
        else:
            return core_ret


    ####################################################################################################################
    def event_handler_exit_process (self):
        '''
        This is the default EXIT_PROCESS_DEBUG_EVENT handler. Calls through to pydbg_core.

        @raise pdx: An exception is raised to denote process exit.
        '''

        core_ret = pydbg_core.event_handler_exit_process(self)

        if self.callbacks.has_key(EXIT_PROCESS_DEBUG_EVENT):
            return self.callbacks[EXIT_PROCESS_DEBUG_EVENT](self)
        else:
            return core_ret


    ####################################################################################################################
    def event_handler_exit_thread (self):
        '''
        This is the default EXIT_THREAD_DEBUG_EVENT handler. Calls through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        core_ret = pydbg_core.event_handler_exit_thread(self)

        if self.callbacks.has_key(EXIT_THREAD_DEBUG_EVENT):
            return self.callbacks[EXIT_THREAD_DEBUG_EVENT](self)
        else:
            return core_ret


    ####################################################################################################################
    def event_handler_load_dll (self):
        '''
        This is the default LOAD_DLL_DEBUG_EVENT handler. Calls through to pydbg_core. You can access the last loaded
        dll in your callback handler with the following example code::

            last_dll = pydbg.get_system_dll(-1)
            print "loading:%s into:%08x size:%d" % (last_dll.name, last_dll.base, last_dll.size)

        The get_system_dll() routine is preferred over directly accessing the internal data structure for proper and
        transparent client/server support.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        core_ret = pydbg_core.event_handler_load_dll(self)

        if self.callbacks.has_key(LOAD_DLL_DEBUG_EVENT):
            return self.callbacks[LOAD_DLL_DEBUG_EVENT](self)
        else:
            return core_ret


    ####################################################################################################################
    def event_handler_unload_dll (self):
        '''
        This is the default UNLOAD_DLL_DEBUG_EVENT handler. Calls through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        core_ret = pydbg_core.event_handler_unload_dll(self)

        if self.callbacks.has_key(UNLOAD_DLL_DEBUG_EVENT):
            return self.callbacks[UNLOAD_DLL_DEBUG_EVENT](self)
        else:
            return core_ret


    ####################################################################################################################
    def exception_handler_access_violation (self):
        '''
        This is the default EXCEPTION_ACCESS_VIOLATION handler. Responsible for handling the access violation and
        passing control to the registered user callback handler. Does not call through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        if self.callbacks.has_key(EXCEPTION_ACCESS_VIOLATION):
            return self.callbacks[EXCEPTION_ACCESS_VIOLATION](self)
        else:
            return DBG_EXCEPTION_NOT_HANDLED


    ####################################################################################################################
    def exception_handler_breakpoint (self):
        '''
        This is the default EXCEPTION_BREAKPOINT handler, responsible for transparently restoring soft breakpoints
        and passing control to the registered user callback handler. Does not call through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        self.pydbg_log("pydbg.exception_handler_breakpoint() at %08x from thread id %d" % (self.exception_address, self.dbg.dwThreadId))

        # breakpoints we did not set.
        if not self.bp_is_ours(self.exception_address):
            # system breakpoints.
            if self.exception_address == self.system_break:
                # pass control to user registered call back.
                if self.callbacks.has_key(EXCEPTION_BREAKPOINT):
                    continue_status = self.callbacks[EXCEPTION_BREAKPOINT](self)
                else:
                    continue_status = DBG_CONTINUE

                if self.first_breakpoint:
                    self.pydbg_log("first windows driven system breakpoint at %08x" % self.exception_address)
                    self.first_breakpoint = False

            # ignore all other breakpoints we didn't explicitly set.
            else:
                self.pydbg_log("breakpoint not ours %08x" % self.exception_address)
                continue_status = DBG_EXCEPTION_NOT_HANDLED

        # breakpoints we did set.
        else:
            # restore the original byte at the breakpoint address.
            self.pydbg_log("restoring original byte at %08x" % self.exception_address)
            self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address].original_byte)
            self.set_attr("dirty", True)

            # before we can continue, we have to correct the value of EIP. the reason for this is that the 1-byte INT 3
            # we inserted causes EIP to "slide" + 1 into the original instruction and must be reset.
            self.set_register("EIP", self.exception_address)
            self.context.Eip -= 1

            # if there is a specific handler registered for this bp, pass control to it.
            if self.breakpoints[self.exception_address].handler:
                self.pydbg_log("calling user handler")
                continue_status = self.breakpoints[self.exception_address].handler(self)

            # pass control to default user registered call back handler, if it is specified.
            elif self.callbacks.has_key(EXCEPTION_BREAKPOINT):
                continue_status = self.callbacks[EXCEPTION_BREAKPOINT](self)

            else:
                continue_status = DBG_CONTINUE

            # if the breakpoint still exists, ie: the user didn't erase it during the callback, and the breakpoint is
            # flagged for restore, then tell the single step handler about it. furthermore, check if the debugger is
            # still active, that way we don't try and single step if the user requested a detach.
            if self.get_attr("debugger_active") and self.breakpoints.has_key(self.exception_address):
                if self.breakpoints[self.exception_address].restore:
                    self._restore_breakpoint = self.breakpoints[self.exception_address]
                    self.single_step(True)

                self.bp_del(self.exception_address)

        return continue_status


    ####################################################################################################################
    def exception_handler_guard_page (self):
        '''
        This is the default EXCEPTION_GUARD_PAGE handler, responsible for transparently restoring memory breakpoints
        passing control to the registered user callback handler. Does not call through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        self.pydbg_log("pydbg.exception_handler_guard_page()")

        # determine the base address of the page where the offending reference resides.
        mbi = self.virtual_query(self.violation_address)

        # if the hit is on a page we did not explicitly GUARD, then pass the violation to the debuggee.
        if mbi.BaseAddress not in self._guarded_pages:
            return DBG_EXCEPTION_NOT_HANDLED

        # determine if the hit was within a monitored buffer, or simply on the same page.
        self.memory_breakpoint_hit = self.bp_is_ours_mem(self.violation_address)

        # grab the actual memory breakpoint object, for the hit breakpoint.
        if self.memory_breakpoint_hit:
            self.pydbg_log("direct hit on memory breakpoint at %08x" % self.memory_breakpoint_hit)

        if self.write_violation:
            self.pydbg_log("write violation from %08x on %08x of mem bp" % (self.exception_address, self.violation_address))
        else:
            self.pydbg_log("read violation from %08x on %08x of mem bp" % (self.exception_address, self.violation_address))

        # if there is a specific handler registered for this bp, pass control to it.
        if self.memory_breakpoint_hit and self.memory_breakpoints[self.memory_breakpoint_hit].handler:
            continue_status = self.memory_breakpoints[self.memory_breakpoint_hit].handler(self)

        # pass control to default user registered call back handler, if it is specified.
        elif self.callbacks.has_key(EXCEPTION_GUARD_PAGE):
            continue_status = self.callbacks[EXCEPTION_GUARD_PAGE](self)

        else:
            continue_status = DBG_CONTINUE

        # if the hit page is still in our list of explicitly guarded pages, ie: the user didn't erase it during the
        # callback, then tell the single step handler about it. furthermore, check if the debugger is still active,
        # that way we don't try and single step if the user requested a detach.
        if self.get_attr("debugger_active") and mbi.BaseAddress in self._guarded_pages:
            self._restore_breakpoint = memory_breakpoint(None, None, mbi, None)
            self.single_step(True)

        return continue_status


    ####################################################################################################################
    def exception_handler_single_step (self):
        '''
        This is the default EXCEPTION_SINGLE_STEP handler, responsible for transparently restoring breakpoints and
        passing control to the registered user callback handler. Does not call through to pydbg_core.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        self.pydbg_log("pydbg.exception_handler_single_step()")

        # if there is a breakpoint to restore.
        if self._restore_breakpoint:
            bp = self._restore_breakpoint

            # restore a soft breakpoint.
            if isinstance(bp, breakpoint):
                self.pydbg_log("restoring breakpoint at 0x%08x" % bp.address)
                self.bp_set(bp.address, bp.description, bp.restore, bp.handler)

            # restore PAGE_GUARD for a memory breakpoint (make sure guards are not temporarily suspended).
            elif isinstance(bp, memory_breakpoint) and self._guards_active:
                self.pydbg_log("restoring %08x +PAGE_GUARD on page based @ %08x" % (bp.mbi.Protect, bp.mbi.BaseAddress))
                self.virtual_protect(bp.mbi.BaseAddress, 1, bp.mbi.Protect | PAGE_GUARD)

            # restore a hardware breakpoint.
            elif isinstance(bp, hardware_breakpoint):
                self.pydbg_log("restoring hardware breakpoint on %08x" % bp.address)
                self.bp_set_hw(bp.address, bp.length, bp.condition, bp.description, bp.restore, bp.handler)

        # determine if this single step event occured in reaction to a hardware breakpoint and grab the hit breakpoint.
        # according to the Intel docs, we should be able to check for the BS flag in Dr6. but it appears that windows
        # isn't properly propogating that flag down to us.
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            self.hardware_breakpoint_hit = self.hardware_breakpoints[0]

        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            self.hardware_breakpoint_hit = self.hardware_breakpoints[1]

        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            self.hardware_breakpoint_hit = self.hardware_breakpoints[2]

        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            self.hardware_breakpoint_hit = self.hardware_breakpoints[3]

        # if we are dealing with a hardware breakpoint and there is a specific handler registered, pass control to it.
        if self.hardware_breakpoint_hit and self.hardware_breakpoint_hit.handler:
            continue_status = self.hardware_breakpoint_hit.handler(self)

        # pass control to default user registered call back handler, if it is specified.
        elif self.callbacks.has_key(EXCEPTION_SINGLE_STEP):
            continue_status = self.callbacks[EXCEPTION_SINGLE_STEP](self)

        # if we single stepped to handle a breakpoint restore.
        elif self._restore_breakpoint:
            continue_status = DBG_CONTINUE

            # macos compatability.
            # need to clear TRAP flag for MacOS. this doesn't hurt Windows aside from a negligible speed hit.
            context         = self.get_thread_context(self.h_thread)
            context.EFlags &= ~EFLAGS_TRAP
            self.set_thread_context(context)

        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        # if we are handling a hardware breakpoint hit and it still exists, ie: the user didn't erase it during the
        # callback, and the breakpoint is flagged for restore, then tell the single step handler about it. furthermore,
        # check if the debugger is still active, that way we don't try and single step if the user requested a detach.
        if self.hardware_breakpoint_hit != None and self.get_attr("debugger_active"):
            slot = self.hardware_breakpoint_hit.slot

            if self.hardware_breakpoints.has_key(slot):
                curr = self.hardware_breakpoints[slot]
                prev = self.hardware_breakpoint_hit

                if curr.address == prev.address:
                    if prev.restore:
                        self._restore_breakpoint = prev
                        self.single_step(True)

                    self.bp_del_hw(slot=prev.slot)

        # reset the hardware breakpoint hit flag and restore breakpoint variable.
        self.hardware_breakpoint_hit = None
        self._restore_breakpoint     = None

        return continue_status


    ####################################################################################################################
    def get_ascii_string (self, data):
        '''
        Retrieve the ASCII string, if any, from data. Ensure that the string is valid by checking against the minimum
        length requirement defined in self.STRING_EXPLORATION_MIN_LENGTH.

        @type  data: Raw
        @param data: Data to explore for printable ascii string

        @rtype:  String
        @return: False on failure, ascii string on discovered string.
        '''

        discovered = ""

        for char in data:
            # if we've hit a non printable char, break
            if ord(char) < 32 or ord(char) > 126:
                break

            discovered += char

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered


    ####################################################################################################################
    def get_arg (self, index, context=None):
        '''
        Given a thread context, this convenience routine will retrieve the function argument at the specified index.
        The return address of the function can be retrieved by specifying an index of 0. This routine should be called
        from breakpoint handlers at the top of a function.

        @type  index:   Integer
        @param index:   Data to explore for printable ascii string
        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  DWORD
        @return: Value of specified argument.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        arg_val = self.read_process_memory(context.Esp + index * 4, 4)
        arg_val = self.flip_endian_dword(arg_val)

        return arg_val


    ####################################################################################################################
    def get_instruction (self, address):
        '''
        Pydasm disassemble utility function wrapper. Returns the pydasm decoded instruction in self.instruction.

        @type  address: DWORD
        @param address: Address to disassemble at

        @rtype:  pydasm instruction
        @return: pydasm instruction
        '''

        try:
            data  = self.read_process_memory(address, 32)
        except:
            return "Unable to disassemble at %08x" % address

        return pydasm.get_instruction(data, pydasm.MODE_32)


    ####################################################################################################################
    def get_printable_string (self, data, print_dots=True):
        '''
        description

        @type  data:       Raw
        @param data:       Data to explore for printable ascii string
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: False on failure, discovered printable chars in string otherwise.
        '''

        discovered = ""

        for char in data:
            if ord(char) >= 32 and ord(char) <= 126:
                discovered += char
            elif print_dots:
                discovered += "."

        return discovered


    ####################################################################################################################
    def get_register (self, register):
        '''
        Get the value of a register in the debuggee within the context of the self.h_thread.

        @type  register: Register
        @param register: One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Value of specified register.
        '''

        self.pydbg_log("getting %s in thread id %d" % (register, self.dbg.dwThreadId))

        register = register.upper()
        if register not in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"):
            raise pdx("invalid register specified")

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        if   register == "EAX": return context.Eax
        elif register == "EBX": return context.Ebx
        elif register == "ECX": return context.Ecx
        elif register == "EDX": return context.Edx
        elif register == "ESI": return context.Esi
        elif register == "EDI": return context.Edi
        elif register == "ESP": return context.Esp
        elif register == "EBP": return context.Ebp
        elif register == "EIP": return context.Eip

        # this shouldn't ever really be reached.
        return 0


    ####################################################################################################################
    def get_unicode_string (self, data):
        '''
        description

        @type  data: Raw
        @param data: Data to explore for printable unicode string

        @rtype:  String
        @return: False on failure, ascii-converted unicode string on discovered string.
        '''

        discovered  = ""
        every_other = True

        for char in data:
            if every_other:
                # if we've hit a non printable char, break
                if ord(char) < 32 or ord(char) > 126:
                    break

                discovered += char

            every_other = not every_other

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered


    ####################################################################################################################
    def hex_dump (self, data, addr=0, prefix=""):
        '''
        Utility function that converts data into hex dump format.

        @type  data:   Raw Bytes
        @param data:   Raw bytes to view in hex dump
        @type  addr:   DWORD
        @param addr:   (Optional, def=0) Address to start hex offset display from
        @type  prefix: String (Optional, def="")
        @param prefix: String to prefix each line of hex dump with.

        @rtype:  String
        @return: Hex dump of data.
        '''

        dump  = prefix
        slice = ""

        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                dump += "\n%s%04x: " % (prefix, addr)
                slice = ""

            dump  += "%02x " % ord(byte)
            slice += byte
            addr  += 1

        remainder = addr % 16

        if remainder != 0:
            dump += "   " * (16 - remainder) + " "

        for char in slice:
            if ord(char) >= 32 and ord(char) <= 126:
                dump += char
            else:
                dump += "."

        return dump + "\n"


    ####################################################################################################################
    def hide_debugger (self):
        '''
        Hide the presence of the debugger. This routine requires an active context and therefore can not be called
        immediately after a load() for example. Call it from the first chance breakpoint handler. This routine hides
        the debugger in the following ways:

            - Modifies the PEB flag that IsDebuggerPresent() checks for.

        @raise pdx: An exception is raised if we are unable to hide the debugger for various reasons.
        '''

        selector_entry = LDT_ENTRY()

        # a current thread context is required.
        if not self.context:
            raise pdx("hide_debugger(): a thread context is required. Call me from a breakpoint handler.")

        if not kernel32.GetThreadSelectorEntry(self.h_thread, self.context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        fs_base  = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # http://openrce.org/reference_library/files/reference/Windows Memory Layout, User-Kernel Address Spaces.pdf
        # find the peb.
        peb = self.read_process_memory(fs_base + 0x30, 4)
        peb = self.flip_endian_dword(peb)

        # zero out the flag. (3rd byte)
        self.write_process_memory(peb+2, "\x00", 1)

        return self.ret_self()


    ####################################################################################################################
    def is_address_on_stack (self, address, context=None):
        '''
        Utility function to determine if the specified address exists on the current thread stack or not.

        @type  address: DWORD
        @param address: Address to check
        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  Bool
        @return: True if address lies in current threads stack range, False otherwise.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        (stack_top, stack_bottom) = self.stack_range(context)

        if address >= stack_bottom and address <= stack_top:
            return True

        return False


    ####################################################################################################################
    def flip_endian (self, dword):
        '''
        Utility function to flip the endianess a given DWORD into raw bytes.

        @type  dword: DWORD
        @param dword: DWORD whose endianess to flip

        @rtype:  Raw Bytes
        @return: Converted DWORD in raw bytes.
        '''

        byte1 = chr(dword % 256)
        dword = dword >> 8
        byte2 = chr(dword % 256)
        dword = dword >> 8
        byte3 = chr(dword % 256)
        dword = dword >> 8
        byte4 = chr(dword % 256)

        return "%c%c%c%c" % (byte1, byte2, byte3, byte4)


    ####################################################################################################################
    def flip_endian_dword (self, bytes):
        '''
        Utility function to flip the endianess of a given set of raw bytes into a DWORD.

        @type  bytes: Raw Bytes
        @param bytes: Raw bytes whose endianess to flip

        @rtype:  DWORD
        @return: Converted DWORD.
        '''

        return struct.unpack("<L", bytes)[0]


    ####################################################################################################################
    def page_guard_clear (self):
        '''
        Clear all debugger-set PAGE_GUARDs from memory. This is useful for suspending memory breakpoints to single step
        past a REP instruction.

        @see: page_guard_restore()

        @rtype:     pydbg
        @return:    Self
        '''

        self._guards_active = False

        for page in self._guarded_pages:
            # make a best effort, let's not crash on failure though.
            try:
                mbi = self.virtual_query(page)
                self.virtual_protect(mbi.BaseAddress, 1, mbi.Protect & ~PAGE_GUARD)
            except:
                pass

        return self.ret_self()


    ####################################################################################################################
    def page_guard_restore (self):
        '''
        Restore all previously cleared debugger-set PAGE_GUARDs from memory. This is useful for suspending memory
        breakpoints to single step past a REP instruction.

        @see: page_guard_clear()

        @rtype:     pydbg
        @return:    Self
        '''

        self._guards_active = True

        for page in self._guarded_pages:
            # make a best effort, let's not crash on failure though.
            try:
                mbi = self.virtual_query(page)
                self.virtual_protect(mbi.BaseAddress, 1, mbi.Protect | PAGE_GUARD)
            except:
                pass

        return self.ret_self()


    ####################################################################################################################
    def process_restore (self):
        '''
        Restore memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # fetch the current list of threads.
        current_thread_list = self.enumerate_threads()

        # restore the thread context for threads still active.
        for thread_context in self.memory_snapshot_contexts:
            if thread_context.thread_id in current_thread_list:
                self.set_thread_context(thread_context.context, thread_id=thread_context.thread_id)

        # restore all saved memory blocks.
        for memory_block in self.memory_snapshot_blocks:
            try:
                self.write_process_memory(memory_block.mbi.BaseAddress, memory_block.data, memory_block.mbi.RegionSize)
            except pdx, x:
                self.pydbg_err("-- IGNORING ERROR --")
                self.pydbg_err("process_restore: " + x.__str__().rstrip("\r\n"))
                pass

        return self.ret_self()


    ####################################################################################################################
    def process_snapshot (self):
        '''
        Take memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("taking debuggee snapshot")

        do_not_snapshot = [PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS]
        cursor          = 0

        # reset the internal snapshot data structure lists.
        self.memory_snapshot_blocks   = []
        self.memory_snapshot_contexts = []

        # enumerate the running threads and save a copy of their contexts.
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(None, thread_id)

            self.memory_snapshot_contexts.append(memory_snapshot_context(thread_id, context))

            self.pydbg_log("saving thread context of thread id: %08x" % thread_id)

        # scan through the entire memory range and save a copy of suitable memory blocks.
        while cursor < 0xFFFFFFFF:
            save_block = True

            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            # do not snapshot blocks of memory that match the following characteristics.
            # XXX - might want to drop the MEM_IMAGE check to accomodate for self modifying code.
            if mbi.State != MEM_COMMIT or mbi.Type == MEM_IMAGE:
                save_block = False

            for has_protection in do_not_snapshot:
                if mbi.Protect & has_protection:
                    save_block = False
                    break

            if save_block:
                self.pydbg_log("Adding %08x +%d to memory snapsnot." % (mbi.BaseAddress, mbi.RegionSize))

                # read the raw bytes from the memory block.
                data = self.read_process_memory(mbi.BaseAddress, mbi.RegionSize)

                self.memory_snapshot_blocks.append(memory_snapshot_block(mbi, data))

            cursor += mbi.RegionSize

        return self.ret_self()


    ####################################################################################################################
    def seh_unwind (self, context=None):
        '''
        Unwind the the Structured Exception Handler (SEH) chain of the current or specified thread to the best of our
        abilities. The SEH chain is a simple singly linked list, the head of which is pointed to by fs:0. In cases where
        the SEH chain is corrupted and the handler address points to invalid memory, it will be returned as 0xFFFFFFFF.

        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  List of Tuples
        @return: Naturally ordered list of SEH addresses and handlers.
        '''

        self.pydbg_log("seh_unwind()")

        selector_entry = LDT_ENTRY()
        seh_chain      = []

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        if not kernel32.GetThreadSelectorEntry(self.h_thread, context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        fs_base  = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # determine the head of the current threads SEH chain.
        seh_head = self.read_process_memory(fs_base, 4)
        seh_head = self.flip_endian_dword(seh_head)

        while seh_head != 0xFFFFFFFF:
            try:
                handler = self.read_process_memory(seh_head + 4, 4)
                handler = self.flip_endian_dword(handler)
            except:
                handler = 0xFFFFFFFF

            try:
                seh_head = self.read_process_memory(seh_head, 4)
                seh_head = self.flip_endian_dword(seh_head)
            except:
                seh_head = 0xFFFFFFFF

            seh_chain.append((seh_head, handler))

        return seh_chain


    ####################################################################################################################
    def set_register (self, register, value):
        '''
        Set the value of a register in the debuggee within the context of the self.h_thread.

        @type  register: Register
        @param register: One of EAX, EBX, ECX, EDX, ESI, EDI, ESP, EBP, EIP
        @type  value:    DWORD
        @param value:    Value to set register to

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self.pydbg_log("setting %s to %08x in thread id %d" % (register, value, self.dbg.dwThreadId))

        register = register.upper()
        if register not in ("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "ESP", "EBP", "EIP"):
            raise pdx("invalid register specified")

        # ensure we have an up to date thread context.
        context = self.get_thread_context(self.h_thread)

        if   register == "EAX": context.Eax = value
        elif register == "EBX": context.Ebx = value
        elif register == "ECX": context.Ecx = value
        elif register == "EDX": context.Edx = value
        elif register == "ESI": context.Esi = value
        elif register == "EDI": context.Edi = value
        elif register == "ESP": context.Esp = value
        elif register == "EBP": context.Ebp = value
        elif register == "EIP": context.Eip = value

        self.set_thread_context(context)

        return self.ret_self()


    ####################################################################################################################
    def smart_dereference (self, address, print_dots=True, hex_dump=False):
        '''
        "Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII
        or Unicode string. In the absense of a string the printable characters are returned with non-printables
        represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or
        the name of the module it lies in (global data).

        @type  address:    DWORD
        @param address:    Address to smart dereference
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  String
        @return: String of data discovered behind dereference.
        '''

        try:
            mbi = self.virtual_query(address)
        except:
            return "N/A"

        # if the address doesn't point into writable memory (stack or heap), then bail.
        if not mbi.Protect & PAGE_READWRITE:
            return "N/A"

        # if the address does point to writeable memory, ensure it doesn't sit on the PEB or any of the TEBs.
        if mbi.BaseAddress == self.peb or mbi.BaseAddress in self.tebs.values():
            return "N/A"

        try:
            explored = self.read_process_memory(address, self.STRING_EXPLORATON_BUF_SIZE)
        except:
            return "N/A"

        # determine if the write-able address sits in the stack range.
        if self.is_address_on_stack(address):
            location = "stack"

        # otherwise it could be in a module's global section or on the heap.
        else:
            module = self.addr_to_module(address)

            if module:
                location = "%s.data" % module.szModule

            # if the write-able address is not on the stack or in a module range, then we assume it's on the heap.
            # we *could* walk the heap structures to determine for sure, but it's a slow method and this process of
            # elimination works well enough.
            else:
                location = "heap"

        explored_string = self.get_ascii_string(explored)

        if not explored_string:
            explored_string = self.get_unicode_string(explored)

        if not explored_string and hex_dump:
            explored_string = self.hex_dump(explored)

        if not explored_string:
            explored_string = self.get_printable_string(explored, print_dots)

        if hex_dump:
            return "%s --> %s" % (explored_string, location)
        else:
            return "%s (%s)" % (explored_string, location)


    ####################################################################################################################
    def stack_range (self, context=None):
        '''
        Determine the stack range (top and bottom) of the current or specified thread. The desired information is
        located at offsets 4 and 8 from the Thread Environment Block (TEB), which in turn is pointed to by fs:0.

        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  Mixed
        @return: List containing (stack_top, stack_bottom) on success, False otherwise.
        '''

        selector_entry = LDT_ENTRY()

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        if not kernel32.GetThreadSelectorEntry(self.h_thread, context.SegFs, byref(selector_entry)):
            self.win32_error("GetThreadSelectorEntry()")

        fs_base  = selector_entry.BaseLow
        fs_base += (selector_entry.HighWord.Bits.BaseMid << 16) + (selector_entry.HighWord.Bits.BaseHi << 24)

        # determine the top and bottom of the debuggee's stack.
        stack_top    = self.read_process_memory(fs_base + 4, 4)
        stack_bottom = self.read_process_memory(fs_base + 8, 4)

        stack_top    = self.flip_endian_dword(stack_top)
        stack_bottom = self.flip_endian_dword(stack_bottom)

        return (stack_top, stack_bottom)


    ####################################################################################################################
    def stack_unwind (self, context=None):
        '''
        Unwind the stack to the best of our ability. This function is really only useful if called when EBP is actually
        used as a frame pointer. If it is otherwise being used as a general purpose register then stack unwinding will
        fail immediately.

        @type  context: Context
        @param context: (Optional) Current thread context to examine

        @rtype:  List
        @return: The current call stack ordered from most recent call backwards.
        '''

        self.pydbg_log("stack_unwind()")

        selector_entry = LDT_ENTRY()
        call_stack     = []

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        # determine the stack top / bottom.
        (stack_top, stack_bottom) = self.stack_range(context)

        this_frame = context.Ebp

        while this_frame > stack_bottom and this_frame < stack_top:
            # stack frame sanity check: must be DWORD boundary aligned.
            if this_frame & 3:
                break

            try:
                ret_addr = self.read_process_memory(this_frame + 4, 4)
                ret_addr = self.flip_endian_dword(ret_addr)
            except:
                break

            # return address sanity check: return address must live on an executable page.
            try:
                mbi = self.virtual_query(ret_addr)
            except:
                break

            if mbi.Protect not in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY):
                break

            # add the return address to the call stack.
            call_stack.append(ret_addr)

            # follow the frame pointer to the next frame.
            try:
                next_frame = self.read_process_memory(this_frame, 4)
                next_frame = self.flip_endian_dword(next_frame)
            except:
                break

            # stack frame sanity check: new frame must be at a higher address then the previous frame.
            if next_frame <= this_frame:
                break

            this_frame = next_frame

        return call_stack


    ####################################################################################################################
    def to_binary (self, number, bit_count=32):
        '''
        Convert a number into a binary string. This is an ugly one liner that I ripped off of some site.

        @see: to_decimal()

        @type  number:    Integer
        @param number:    Number to convert to binary string.
        @type  bit_count: Integer
        @param bit_count: (Optional, Def=32) Number of bits to include in output string.

        @rtype:  String
        @return: Specified integer as a binary string
        '''

        return "".join(map(lambda x:str((number >> x) & 1), range(bit_count -1, -1, -1)))


    ####################################################################################################################
    def to_decimal (self, binary):
        '''
        Convert a binary string into a decimal number.

        @see: to_binary()

        @type  binary: String
        @param binary: Binary string to convert to decimal

        @rtype:  Integer
        @return: Specified binary string as an integer
        '''

        # this is an ugly one liner that I ripped off of some site.
        #return sum(map(lambda x: int(binary[x]) and 2**(len(binary) - x - 1), range(len(binary)-1, -1, -1)))

        # this is much cleaner (thanks cody)
        return int(binary, 2)
