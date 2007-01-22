#
# Crash Binning
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
@author:       Pedram Amini
@license:      GNU General Public License 2.0 or later
@contact:      pedram.amini@gmail.com
@organization: www.openrce.org
'''

class __crash_bin_struct__:
    exception_address   = 0
    write_violation     = 0
    violation_address   = 0
    violation_thread_id = 0
    context             = None
    context_dump        = None
    disasm              = None
    disasm_around       = []
    stack_unwind        = []
    seh_unwind          = []
    extra               = None


class crash_binning:
    '''
    @todo: Add persistant data support (disk / MySQL)
    '''

    bins       = {}
    last_crash = None
    pydbg      = None

    ####################################################################################################################
    def __init__ (self):
        '''
        '''

        self.bins       = {}
        self.last_crash = None
        self.pydbg      = None


    ####################################################################################################################
    def record_crash (self, pydbg, extra=None):
        '''
        Given a PyDbg instantiation that at the current time is assumed to have "crashed" (access violation for example)
        record various details such as the disassemly around the violating address, the ID of the offending thread, the
        call stack and the SEH unwind. Store the recorded data in an internal dictionary, binning them by the exception
        address.

        @type  pydbg: pydbg
        @param pydbg: Instance of pydbg
        @type  extra: Mixed
        @param extra: (Optional, Def=None) Whatever extra data you want to store with this bin
        '''

        self.pydbg = pydbg
        crash = __crash_bin_struct__()

        crash.exception_address   = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress
        crash.exception_module    = pydbg.addr_to_module(crash.exception_address).szModule
        crash.write_violation     = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        crash.violation_address   = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]
        crash.violation_thread_id = pydbg.dbg.dwThreadId
        crash.context             = pydbg.context
        crash.context_dump        = pydbg.dump_context(pydbg.context, print_dots=False)
        crash.disasm              = pydbg.disasm(crash.exception_address)
        crash.disasm_around       = pydbg.disasm_around(crash.exception_address)
        crash.stack_unwind        = pydbg.stack_unwind()
        crash.seh_unwind          = pydbg.seh_unwind()
        crash.extra               = extra

        # add module information to the stack and seh unwind.
        for i in xrange(len(crash.stack_unwind)):
            addr = crash.stack_unwind[i]
            crash.stack_unwind[i] = "%s:%08x" % (pydbg.addr_to_module(addr).szModule, addr)

        for i in xrange(len(crash.seh_unwind)):
            (addr, handler) = crash.seh_unwind[i]
            crash.seh_unwind[i] = (addr, handler, "%s:%08x" % (pydbg.addr_to_module(handler).szModule, handler))

        if not self.bins.has_key(crash.exception_address):
            self.bins[crash.exception_address] = []

        self.bins[crash.exception_address].append(crash)
        self.last_crash = crash


    ####################################################################################################################
    def crash_synopsis (self):
        '''
        For the last recorded crash, generate and return a report containing the disassemly around the violating
        address, the ID of the offending thread, the call stack and the SEH unwind.
        '''

        if self.last_crash.write_violation:
            direction = "write to"
        else:
            direction = "read from"

        synopsis = "%s:%08x %s from thread %d caused access violation\nwhen attempting to %s 0x%08x\n\n" % \
            (
                self.last_crash.exception_module,       \
                self.last_crash.exception_address,      \
                self.last_crash.disasm,                 \
                self.last_crash.violation_thread_id,    \
                direction,                              \
                self.last_crash.violation_address       \
            )

        synopsis += self.last_crash.context_dump

        synopsis += "\ndisasm around:\n"
        for (ea, inst) in self.last_crash.disasm_around:
            synopsis += "\t0x%08x %s\n" % (ea, inst)

        if len(self.last_crash.stack_unwind):
            synopsis += "\nstack unwind:\n"
            for entry in self.last_crash.stack_unwind:
                synopsis += "\t%s\n" % entry

        if len(self.last_crash.seh_unwind):
            synopsis += "\nSEH unwind:\n"
            for (addr, handler, handler_str) in self.last_crash.seh_unwind:
                try:
                    disasm = self.pydbg.disasm(handler)
                except:
                    disasm = "[INVALID]"

                synopsis +=  "\t%08x -> %s\t%s\n" % (addr, handler_str, disasm)

        return synopsis + "\n"