#!c:\python\python.exe

#
# PyDBG
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

import sys
import signal

from my_ctypes  import *
from defines    import *
from windows_h  import *
from system_dll import *

ntdll    = windll.ntdll
kernel32 = windll.kernel32
advapi32 = windll.advapi32

from pdx import *

class pydbg_core(object):
    '''
    This is the core debugger class from which extended debugger functionality should be derived. This class contains:

        - The load() / attach() routines.
        - The main debug event loop.
        - Convenience wrappers for commonly used Windows API.
        - Single step toggling routine.
        - Win32 error handler wrapped around PDX.
        - Base exception / event handler routines which are meant to be overridden.
    '''

    page_size         = 0          # memory page size (dynamically resolved at run-time)
    pid               = 0          # debuggee's process id
    h_process         = None       # debuggee's process handle
    h_thread          = None       # handle to current debuggee thread
    debugger_active   = True       # flag controlling the main debugger event handling loop
    follow_forks      = False      # flag controlling whether or not pydbg attaches to forked processes
    client_server     = False      # flag controlling whether or not pydbg is in client/server mode
    callbacks         = {}         # exception callback handler dictionary
    system_dlls       = []         # list of loaded system dlls
    dirty             = False      # flag specifying that the memory space of the debuggee was modified
    system_break      = None       # the address at which initial and forced breakpoints occur at

    # internal variables specific to the last triggered exception.
    context           = None       # thread context of offending thread
    dbg               = None       # DEBUG_EVENT
    exception_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionAddress
    write_violation   = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
    violation_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

    ####################################################################################################################
    def __init__ (self, ff=True, cs=False):
        '''
        Set the default attributes. See the source if you want to modify the default creation values.

        @type  ff: Boolean
        @param ff: (Optional, Def=True) Flag controlling whether or not pydbg attaches to forked processes
        '''

        self.page_size         = 0          # memory page size (dynamically resolved at run-time)
        self.pid               = 0          # debuggee's process id
        self.h_process         = None       # debuggee's process handle
        self.h_thread          = None       # handle to current debuggee thread
        self.debugger_active   = True       # flag controlling the main debugger event handling loop
        self.follow_forks      = ff         # flag controlling whether or not pydbg attaches to forked processes
        self.client_server     = cs         # flag controlling whether or not pydbg is in client/server mode
        self.callbacks         = {}         # exception callback handler dictionary
        self.system_dlls       = []         # list of loaded system dlls
        self.dirty             = False      # flag specifying that the memory space of the debuggee was modified

        # internal variables specific to the last triggered exception.
        self.context           = None       # thread context of offending thread
        self.dbg               = None       # DEBUG_EVENT
        self.exception_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionAddress
        self.write_violation   = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
        self.violation_address = None       # from dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

        # control debug/error logging.
        self.core_log = lambda msg: None
        self.core_err = lambda msg: sys.stderr.write("CORE_ERR> " + msg + "\n")

        # determine the system page size.
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize

        # determine the system DbgBreakPoint address. this is the address at which initial and forced breaks happen.
        # XXX - need to look into fixing this for pydbg client/server.
        self.system_break = self.func_resolve("ntdll.dll", "DbgBreakPoint")

        self.core_log("system page size is %d" % self.page_size)


    ####################################################################################################################
    def addr_to_dll (self, address):
        '''
        Return the system DLL that contains the address specified.

        @type  address: DWORD
        @param address: Address to search system DLL ranges for

        @rtype:  system_dll
        @return: System DLL that contains the address specified or None if not found.
        '''

        for dll in self.system_dlls:
            if dll.base < address < dll.base + dll.size:
                return dll

        return None


    ####################################################################################################################
    def addr_to_module (self, address):
        '''
        Return the MODULEENTRY32 structure for the module that contains the address specified.

        @type  address: DWORD
        @param address: Address to search loaded module ranges for

        @rtype:  MODULEENTRY32
        @return: MODULEENTRY32 strucutre that contains the address specified or None if not found.
        '''

        for module in self.iterate_modules():
            if module.modBaseAddr < address < module.modBaseAddr + module.modBaseSize:
                return module

        return None


    ####################################################################################################################
    def attach (self, pid):
        '''
        Attach to the specified process by PID. Saves a process handle in self.h_process and prevents debuggee from
        exiting on debugger quit.

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("attaching to pid %d" % pid)

        # obtain necessary debug privileges.
        self.get_debug_privileges()

        self.pid       = pid
        self.h_process = self.open_process(pid)

        self.debug_active_process(pid)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        return self.ret_self()


    ####################################################################################################################
    def cleanup (self):
        '''
        Clean up after ourselves.

        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("pydbg_core cleaning up")

        # ensure no threads are suspended or in single step mode.
        for thread_id in self.enumerate_threads():
            self.resume_thread(thread_id)

            try:
                handle = self.open_thread(thread_id)
                self.single_step(False, handle)
                self.close_handle(handle)
            except:
                pass

        return self.ret_self()


    ####################################################################################################################
    def close_handle (self, handle):
        '''
        Convenience wraper around kernel32.CloseHandle().

        @type  handle: Handle
        @param handle: Handle to close

        @rtype:  Bool
        @return: Return value from CloseHandle().
        '''

        return kernel32.CloseHandle(handle)


    ####################################################################################################################
    def debug_active_process (self, pid):
        '''
        Convenience wrapper around GetLastError() and FormatMessage(). Returns the error code and formatted message
        associated with the last error. You probably do not want to call this directly, rather look at attach().

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        '''

        if not kernel32.DebugActiveProcess(pid):
            raise pdx("DebugActiveProcess(%d)" % pid, True)


    ####################################################################################################################
    def debug_event_iteration (self):
        '''
        Check for and process a debug event.
        '''

        continue_status = DBG_CONTINUE
        dbg             = DEBUG_EVENT()

        # wait for a debug event.
        if kernel32.WaitForDebugEvent(byref(dbg), 100):
            # grab various information with regards to the current exception.
            self.h_thread          = self.open_thread(dbg.dwThreadId)
            self.context           = self.get_thread_context(self.h_thread)
            self.dbg               = dbg
            self.exception_address = dbg.u.Exception.ExceptionRecord.ExceptionAddress
            self.write_violation   = dbg.u.Exception.ExceptionRecord.ExceptionInformation[0]
            self.violation_address = dbg.u.Exception.ExceptionRecord.ExceptionInformation[1]

            if dbg.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                continue_status = self.event_handler_create_process()
                self.close_handle(self.dbg.u.CreateProcessInfo.hFile)

            elif dbg.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                continue_status = self.event_handler_create_thread()

            elif dbg.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                continue_status = self.event_handler_exit_process()

            elif dbg.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                continue_status = self.event_handler_exit_thread()

            elif dbg.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                continue_status = self.event_handler_load_dll()
                self.close_handle(self.dbg.u.LoadDll.hFile)

            elif dbg.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
                continue_status = self.event_handler_unload_dll()

            # an exception was caught.
            elif dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                ec = dbg.u.Exception.ExceptionRecord.ExceptionCode

                self.core_log("debug_event_loop() exception: %08x" % ec)

                # call the internal handler for the exception event that just occured.
                if ec == EXCEPTION_ACCESS_VIOLATION:
                    continue_status = self.exception_handler_access_violation()
                elif ec == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint()
                elif ec == EXCEPTION_GUARD_PAGE:
                    continue_status = self.exception_handler_guard_page()
                elif ec == EXCEPTION_SINGLE_STEP:
                    continue_status = self.exception_handler_single_step()
                # generic callback support.
                elif self.callbacks.has_key(ec):
                    continue_status = self.callbacks[ec](self)
                # unhandled exception.
                else:
                    self.core_log("TID:%04x caused an unhandled exception (%08x) at %08x" % (self.dbg.dwThreadId, ec, self.exception_address))
                    continue_status = DBG_EXCEPTION_NOT_HANDLED

            # if the memory space of the debuggee was tainted, flush the instruction cache.
            # from MSDN: Applications should call FlushInstructionCache if they generate or modify code in memory.
            #            The CPU cannot detect the change, and may execute the old code it cached.
            if self.dirty:
                kernel32.FlushInstructionCache(self.h_process, 0, 0)

            # close the opened thread handle and resume executing the thread that triggered the debug event.
            self.close_handle(self.h_thread)
            kernel32.ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, continue_status)

    ####################################################################################################################
    def debug_event_loop (self):
        '''
        Enter the infinite debug event handling loop. This is the main loop of the debugger and is responsible for
        catching debug events and exceptions and dispatching them appropriately. This routine will check for and call
        the USER_CALLBACK_DEBUG_EVENT callback on each loop iteration. run() is an alias for this routine.

        @see: run()

        @raise pdx: An exception is raised on any exceptional conditions, such as debugger being interrupted or
        debuggee quiting.
        '''

        while self.debugger_active:
            # don't let the user interrupt us in the midst of handling a debug event.
            try:
                def_sigint_handler = None
                def_sigint_handler = signal.signal(signal.SIGINT, self.sigint_handler)
            except:
                pass

            # if a user callback was specified, call it.
            if self.callbacks.has_key(USER_CALLBACK_DEBUG_EVENT):
                # user callbacks do not / should not access debugger or contextual information.
                self.dbg = self.context = None
                self.callbacks[USER_CALLBACK_DEBUG_EVENT](self)

            # iterate through a debug event.

            self.debug_event_iteration()

            # resume keyboard interruptability.
            if def_sigint_handler:
                signal.signal(signal.SIGINT, def_sigint_handler)

        # if the process is still around, detach (if that is supported on the current system) from it.
        try:
            self.detach()
        except:
            pass


    ####################################################################################################################
    def debug_set_process_kill_on_exit (self, kill_on_exit):
        '''
        Convenience wrapper around DebugSetProcessKillOnExit().

        @type  kill_on_exit: Bool
        @param kill_on_exit: True to kill the process on debugger exit, False to let debuggee continue running.

        @raise pdx: An exception is raised on failure.
        '''

        if not kernel32.DebugSetProcessKillOnExit(kill_on_exit):
            raise pdx("DebugActiveProcess(%s)" % kill_on_exit, True)


    ####################################################################################################################
    def detach (self):
        '''
        Detach from debuggee.
        '''

        self.core_log("detaching from debuggee")

        # if we're not attached to a process, we have nothing to do.
        if not self.pid:
            return

        self.cleanup()
        self.set_debugger_active(False)

        # try to detach from the target process if the API is available on the current platform.
        try:
            kernel32.DebugActiveProcessStop(self.pid)
        except:
            pass


    #####################################################################################################################
    def enumerate_modules (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate and return the list of module name / base address tuples that
        belong to the debuggee

        @see: iterate_modules()

        @rtype:  List
        @return: List of module name / base address tuples.
        '''

        self.core_log("enumerate_modules()")

        module      = MODULEENTRY32()
        module_list = []
        snapshot    = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        module.dwSize = sizeof(module)

        found_mod = kernel32.Module32First(snapshot, byref(module))

        while found_mod:
            module_list.append((module.szModule, module.modBaseAddr))
            found_mod = kernel32.Module32Next(snapshot, byref(module))

        kernel32.CloseHandle(snapshot)
        return module_list


    ####################################################################################################################
    def enumerate_processes (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system processes returning a list of pid / process name
        tuples.

        @see: iterate_processes()

        @rtype:  List
        @return: List of pid / process name tuples.

        Example::

            for (pid, name) in pydbg.enumerate_processes():
                if name == "test.exe":
                    break

            pydbg.attach(pid)
        '''

        self.core_log("enumerate_processes()")

        pe           = PROCESSENTRY32()
        process_list = []
        snapshot     = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        found_proc = kernel32.Process32First(snapshot, byref(pe))

        while found_proc:
            process_list.append((pe.th32ProcessID, pe.szExeFile))
            found_proc = kernel32.Process32Next(snapshot, byref(pe))

        kernel32.CloseHandle(snapshot)
        return process_list


    ####################################################################################################################
    def enumerate_threads (self):
        '''
        Using the CreateToolhelp32Snapshot() API enumerate all system threads returning a list of thread IDs that
        belong to the debuggee.

        @see: iterate_threads()

        @rtype:  List
        @return: List of thread IDs belonging to the debuggee.

        Example::
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)
        '''

        self.core_log("enumerate_threads()")

        thread_entry     = THREADENTRY32()
        debuggee_threads = []
        snapshot         = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        success = kernel32.Thread32First(snapshot, byref(thread_entry))

        while success:
            if thread_entry.th32OwnerProcessID == self.pid:
                debuggee_threads.append(thread_entry.th32ThreadID)

            success = kernel32.Thread32Next(snapshot, byref(thread_entry))

        kernel32.CloseHandle(snapshot)
        return debuggee_threads


    ####################################################################################################################
    def event_handler_create_process (self):
        '''
        This is the default CREATE_PROCESS_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_create_thread (self):
        '''
        This is the default CREATE_THREAD_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_exit_process (self):
        '''
        This is the default EXIT_PROCESS_DEBUG_EVENT handler.

        @raise pdx: An exception is raised to denote process exit.
        '''

        self.set_debugger_active(False)
        self.close_handle(self.h_process)

        self.pid = self.h_process = None

        return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_exit_thread (self):
        '''
        This is the default EXIT_THREAD_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_load_dll (self):
        '''
        This is the default LOAD_DLL_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        dll = system_dll(self.dbg.u.LoadDll.hFile, self.dbg.u.LoadDll.lpBaseOfDll)
        self.system_dlls.append(dll)

        return DBG_CONTINUE


    ####################################################################################################################
    def event_handler_unload_dll (self):
        '''
        This is the default UNLOAD_DLL_DEBUG_EVENT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        base     = self.dbg.u.UnloadDll.lpBaseOfDll
        unloaded = None

        for system_dll in self.system_dlls:
            if system_dll.base == base:
                unloaded = system_dll
                break

        if not unloaded:
            #raise pdx("Unable to locate DLL that is being unloaded from %08x" % base, False)
            pass
        else:
            self.system_dlls.remove(unloaded)

        return DBG_CONTINUE


    ####################################################################################################################
    def exception_handler_access_violation (self):
        '''
        This is the default EXCEPTION_ACCESS_VIOLATION handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED


    ####################################################################################################################
    def exception_handler_breakpoint (self):
        '''
        This is the default EXCEPTION_BREAKPOINT handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED


    ####################################################################################################################
    def exception_handler_guard_page (self):
        '''
        This is the default EXCEPTION_GUARD_PAGE handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED


    ####################################################################################################################
    def exception_handler_single_step (self):
        '''
        This is the default EXCEPTION_SINGLE_STEP handler.

        @rtype:  DWORD
        @return: Debug event continue status.
        '''

        return DBG_EXCEPTION_NOT_HANDLED


    ####################################################################################################################
    def get_attr (self, attribute):
        '''
        Return the value for the specified class attribute. This routine should be used over directly accessing class
        member variables for transparent support across local vs. client/server debugger clients.

        @see: set_attr()

        @type  attribute: String
        @param attribute: Name of attribute to return.

        @rtype:  Mixed
        @return: Requested attribute or None if not found.
        '''

        if not hasattr(self, attribute):
            return None

        return getattr(self, attribute)


    ####################################################################################################################
    def get_debug_privileges (self):
        '''
        Obtain necessary privileges for debugging.

        @raise pdx: An exception is raised on failure.
        '''

        h_token     = HANDLE()
        luid        = LUID()
        token_state = TOKEN_PRIVILEGES()

        self.core_log("get_debug_privileges()")

        current_process = kernel32.GetCurrentProcess()

        if not advapi32.OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES, byref(h_token)):
            raise pdx("OpenProcessToken()", True)

        if not advapi32.LookupPrivilegeValueA(0, "seDebugPrivilege", byref(luid)):
            raise pdx("LookupPrivilegeValue()", True)

        token_state.PrivilegeCount = 1
        token_state.Privileges[0].Luid = luid
        token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if not advapi32.AdjustTokenPrivileges(h_token, 0, byref(token_state), 0, 0, 0):
            raise pdx("AdjustTokenPrivileges()", True)


    ####################################################################################################################
    def get_system_dll (self, idx):
        '''
        Return the system DLL at the specified index. If the debugger is in client / server mode, remove the PE
        structure (we do not want to send that mammoth over the wire).

        @type  idx: Integer
        @param idx: Index into self.system_dlls[] to retrieve DLL from.

        @rtype:  Mixed
        @return: Requested attribute or None if not found.
        '''

        self.core_log("get_system_dll()")

        try:
            dll = self.system_dlls[idx]
        except:
            # index out of range.
            return None

        dll.pe = None
        return dll


    ####################################################################################################################
    def get_thread_context (self, thread_handle, thread_id=0):
        '''
        Convenience wrapper around GetThreadContext(). Can obtain a thread context via a handle or thread id.

        @type  thread_handle: HANDLE
        @param thread_handle: (Optional) Handle of thread to get context of
        @type  thread_id:     Integer
        @param thread_id:     (Optional, Def=0) ID of thread to get context of

        @raise pdx: An exception is raised on failure.
        @rtype:     CONTEXT
        @return:    Thread CONTEXT on success.
        '''

        context = CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        # if a thread handle was not specified, get one from the thread id.
        if not thread_handle:
            h_thread = self.open_thread(thread_id)
        else:
            h_thread = thread_handle

        if not kernel32.GetThreadContext(h_thread, byref(context)):
            raise pdx("GetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle:
            kernel32.CloseHandle(h_thread)

        return context


    #####################################################################################################################
    def iterate_modules (self):
        '''
        A simple iterator function that can be used to iterate through all modules the target process has mapped in its
        address space. Yielded objects are of type MODULEENTRY32.

        @author: Otto Ebeling
        @see:    enumerate_modules()

        @rtype:  MODULEENTRY32
        @return: Iterated module entries.
        '''

        self.core_log("iterate_modules()")

        current_entry = MODULEENTRY32()
        snapshot      = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Module32First() will fail.
        current_entry.dwSize = sizeof(current_entry)

        if not kernel32.Module32First(snapshot, byref(current_entry)):
            return

        while 1:
            yield current_entry

            if not kernel32.Module32Next(snapshot, byref(current_entry)):
                break

        kernel32.CloseHandle(snapshot)


    #####################################################################################################################
    def iterate_processes (self):
        '''
        A simple iterator function that can be used to iterate through all running processes. Yielded objects are of
        type PROCESSENTRY32.

        @see: enumerate_processes()

        @rtype:  PROCESSENTRY32
        @return: Iterated process entries.
        '''

        self.core_log("iterate_processes()")

        pe       = PROCESSENTRY32()
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0", True)

        # we *must* set the size of the structure prior to using it, otherwise Process32First() will fail.
        pe.dwSize = sizeof(PROCESSENTRY32)

        if not kernel32.Process32First(snapshot, byref(pe)):
            return

        while 1:
            yield pe

            if not kernel32.Process32Next(snapshot, byref(pe)):
                break

        kernel32.CloseHandle(snapshot)


    #####################################################################################################################
    def iterate_threads (self):
        '''
        A simple iterator function that can be used to iterate through all running processes. Yielded objects are of
        type PROCESSENTRY32.

        @see: enumerate_threads()

        @rtype:  PROCESSENTRY32
        @return: Iterated process entries.
        '''

        self.core_log("iterate_threads()")

        thread_entry = THREADENTRY32()
        snapshot     = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid)

        if snapshot == INVALID_HANDLE_VALUE:
            raise pdx("CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, %d" % self.pid, True)

        # we *must* set the size of the structure prior to using it, otherwise Thread32First() will fail.
        thread_entry.dwSize = sizeof(thread_entry)

        if not kernel32.Thread32First(snapshot, byref(thread_entry)):
            return

        while 1:
            if thread_entry.th32OwnerProcessID == self.pid:
                yield thread_entry

            if not kernel32.Thread32Next(snapshot, byref(thread_entry)):
                break

        kernel32.CloseHandle(snapshot)


    ####################################################################################################################
    def load (self, path_to_file, command_line=None):
        '''
        Load the specified executable and optional command line arguments into the debugger.

        @todo: This routines needs to be further tested ... I nomally just attach.

        @type  path_to_file: String
        @param path_to_file: Full path to executable to load in debugger
        @type  command_line: String
        @param command_line: (Optional, def=None) Command line arguments to pass to debuggee

        @raise pdx: An exception is raised if we are unable to load the specified executable in the debugger.
        '''

        pi = PROCESS_INFORMATION()
        si = STARTUPINFO()

        si.cb = sizeof(si);

        # CreateProcess() seems to work better with command line arguments when the path_to_file is passed as NULL.
        if command_line:
            command_line = path_to_file + " " + command_line
            path_to_file = 0

        if self.follow_forks:
            creation_flags = DEBUG_PROCESS
        else:
            creation_flags = DEBUG_ONLY_THIS_PROCESS

        success = kernel32.CreateProcessA(c_char_p(path_to_file),
                                          c_char_p(command_line),
                                          0,
                                          0,
                                          0,
                                          creation_flags,
                                          0,
                                          0,
                                          byref(si),
                                          byref(pi))

        if not success:
            raise pdx("CreateProcess()", True)

        # allow detaching on systems that support it.
        try:
            self.debug_set_process_kill_on_exit(False)
        except:
            pass

        '''
        If the function succeeds, be sure to call the CloseHandle function to close the hProcess and hThread handles when you are finished with them. -bill gates
        '''

        self.close_handle(pi.hThread)

        self.pid       = pi.dwProcessId
        self.h_process = pi.hProcess


    ####################################################################################################################
    def open_process (self, pid):
        '''
        Convenience wrapper around OpenProcess().

        @type  pid: Integer
        @param pid: Process ID to attach to

        @raise pdx: An exception is raised on failure.
        '''

        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

        if not h_process:
            raise pdx("OpenProcess(%d)" % pid, True)

        return h_process


    ####################################################################################################################
    def open_thread (self, thread_id):
        '''
        Convenience wrapper around OpenThread().

        @type  thread_id: Integer
        @param thread_id: ID of thread to obtain handle to

        @raise pdx: An exception is raised on failure.
        '''

        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, thread_id)

        if not h_thread:
            raise pdx("OpenThread(%d)" % thread_id, True)

        return h_thread


    ####################################################################################################################
    def read (self, address, length):
        '''
        Alias to read_process_memory().

        @see: read_process_memory
        '''

        return self.read_process_memory(address, length)


    ####################################################################################################################
    def read_msr (self, address):
        '''
        Read data from the specified MSR address.

        @see: write_msr

        @type  address: DWORD
        @param address: MSR address to read from.

        @rtype:  tuple
        @return: (read status, msr structure)
        '''

        msr         = SYSDBG_MSR()
        msr.Address = 0x1D9
        msr.Data    = 0xFF  # must initialize this value.

        status = ntdll.NtSystemDebugControl(SysDbgReadMsr,
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            0);

        return (status, msr)


    ####################################################################################################################
    def read_process_memory (self, address, length):
        '''
        Read from the debuggee process space.

        @type  address: DWORD
        @param address: Address to read from.
        @type  length:  Integer
        @param length:  Length, in bytes, of data to read.

        @raise pdx: An exception is raised on failure.
        @rtype:     Raw
        @return:    Read data.
        '''

        data         = ""
        read_buf     = create_string_buffer(length)
        count        = c_ulong(0)
        orig_length  = length
        orig_address = address

        # ensure we can read from the requested memory space.
        _address = address
        _length  = length

        try:
            old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        while length:
            if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
                raise pdx("ReadProcessMemory(%08x, %d, read=%d)" % (address, length, count.value), True)

            data    += read_buf.raw
            length  -= count.value
            address += count.value

        # restore the original page permissions on the target memory region.
        try:
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass

        return data


    ####################################################################################################################
    def resume_all_threads (self):
        '''
        Resume all process threads.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        for thread_id in self.enumerate_threads():
            self.resume_thread(thread_id)

        return self.ret_self()


    ####################################################################################################################
    def resume_thread (self, thread_id):
        '''
        Resume the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to resume.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("resuming thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        if kernel32.ResumeThread(thread_handle) == -1:
            raise pdx("ResumeThread()", True)

        kernel32.CloseHandle(thread_handle)

        return self.ret_self()


    ####################################################################################################################
    def ret_self (self):
        '''
        This convenience routine exists for internal functions to call and transparently return the correct version of
        self. Specifically, an object in normal mode and a moniker when in client/server mode.

        @return: Client / server safe version of self
        '''

        if self.client_server:
            return "**SELF**"
        else:
            return self


    ####################################################################################################################
    def run (self):
        '''
        Alias for debug_event_loop().

        @see: debug_event_loop()
        '''

        self.debug_event_loop()


    ####################################################################################################################
    def set_attr (self, attribute, value):
        '''
        Return the value for the specified class attribute. This routine should be used over directly accessing class
        member variables for transparent support across local vs. client/server debugger clients.

        @see: set_attr()

        @type  attribute: String
        @param attribute: Name of attribute to return.
        @type  value:     Mixed
        @param value:     Value to set attribute to.
        '''

        if hasattr(self, attribute):
            setattr(self, attribute, value)


    ####################################################################################################################
    def set_callback (self, exception_code, callback_func):
        '''
        Set a callback for the specified exception (or debug event) code. The prototype of the callback routines is::

            func (pydbg):
                return DBG_CONTINUE     # or other continue status

        You can register callbacks for any exception code or debug event. Look in the source for all event_handler_xxx
        and exception_handler_xxx routines to see which ones have internal processing (internal handlers will still
        pass control to your callback). You can also register a user specified callback that is called on each loop
        iteration from within debug_event_loop(). The callback code is USER_CALLBACK_DEBUG_EVENT and the function
        prototype is::

            func (pydbg)
                return DBG_CONTINUE     # or other continue status

        @type  exception_code: Long
        @param exception_code: Exception code to establish a callback for
        @type  callback_func:  Function
        @param callback_func:  Function to call when specified exception code is caught.
        '''

        self.callbacks[exception_code] = callback_func


    ####################################################################################################################
    def set_debugger_active (self, enable):
        '''
        Enable or disable the control flag for the main debug event loop. This is a convenience shortcut over set_attr.

        @type  enable: Boolean
        @param enable: Flag controlling the main debug event loop.
        '''

        self.core_log("setting debug event loop flag to %s" % enable)

        self.debugger_active = enable


    ####################################################################################################################
    def set_thread_context (self, context, thread_handle=None, thread_id=0):
        '''
        Convenience wrapper around SetThreadContext(). Can set a thread context via a handle or thread id.

        @type  thread_handle: HANDLE
        @param thread_handle: (Optional) Handle of thread to get context of
        @type  context:       CONTEXT
        @param context:       Context to apply to specified thread
        @type  thread_id:     Integer
        @param thread_id:     (Optional, Def=0) ID of thread to get context of

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        # if neither a thread handle or thread id were specified, default to the internal one.
        if not thread_handle and not thread_id:
            h_thread = self.h_thread

        # if a thread handle was not specified, get one from the thread id.
        elif not thread_handle:
            h_thread = self.open_thread(thread_id)

        # use the specified thread handle.
        else:
            h_thread = thread_handle

        if not kernel32.SetThreadContext(h_thread, byref(context)):
            raise pdx("SetThreadContext()", True)

        # if we had to resolve the thread handle, close it.
        if not thread_handle and thread_id:
            kernel32.CloseHandle(h_thread)

        return self.ret_self()


    ####################################################################################################################
    def sigint_handler (self, signal_number, stack_frame):
        '''
        Interrupt signal handler. We override the default handler to disable the run flag and exit the main
        debug event loop.

        @type  signal_number:
        @param signal_number:
        @type  stack_frame:
        @param stack_frame:
        '''

        self.set_debugger_active(False)


    ####################################################################################################################
    def single_step (self, enable, thread_handle=None):
        '''
        Enable or disable single stepping in the specified thread or self.h_thread if a thread handle is not specified.

        @type  enable:        Bool
        @param enable:        True to enable single stepping, False to disable
        @type  thread_handle: Handle
        @param thread_handle: (Optional, Def=None) Handle of thread to put into single step mode

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("single_step(%s)" % enable)

        if not thread_handle:
            thread_handle = self.h_thread

        context = self.get_thread_context(thread_handle)

        if enable:
            # single step already enabled.
            if context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags |= EFLAGS_TRAP
        else:
            # single step already disabled:
            if not context.EFlags & EFLAGS_TRAP:
                return self.ret_self()

            context.EFlags = context.EFlags & (0xFFFFFFFFFF ^ EFLAGS_TRAP)

        self.set_thread_context(context, thread_handle=thread_handle)

        return self.ret_self()


    ####################################################################################################################
    def suspend_all_threads (self):
        '''
        Suspend all process threads.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        for thread_id in self.enumerate_threads():
            self.suspend_thread(thread_id)

        return self.ret_self()


    ####################################################################################################################
    def suspend_thread (self, thread_id):
        '''
        Suspend the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to suspend

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg_core
        @return:    Self
        '''

        self.core_log("suspending thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        if kernel32.SuspendThread(thread_handle) == -1:
            raise pdx("SuspendThread()", True)

        kernel32.CloseHandle(thread_handle)

        return self.ret_self()


    ####################################################################################################################
    def terminate_process (self, exit_code=0):
        '''
        Terminate the debuggee.

        @type  exit_code: Integer
        @param exit_code: (Optional, def=0) Exit code

        @raise pdx: An exception is raised on failure.
        '''

        self.set_debugger_active(False)

        try:
            if not kernel32.TerminateProcess(self.h_process, exit_code):
                raise pdx("TerminateProcess(%d)" % exit_code, True)
        finally:
                self.close_handle(self.h_process)

        return False


    ####################################################################################################################
    def virtual_alloc (self, address, size, alloc_type, protection):
        '''
        Convenience wrapper around VirtualAllocEx()

        @type  address:    DWORD
        @param address:    Desired starting address of region to allocate, can be None
        @type  size:       Integer
        @param size:       Size of memory region to allocate, in bytes
        @type  alloc_type: DWORD
        @param alloc_type: The type of memory allocation (most often MEM_COMMIT)
        @type  protection: DWORD
        @param protection: Memory protection to apply to the specified region

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Base address of the allocated region of pages.
        '''

        if address:
            self.core_log("VirtualAllocEx(%08x, %d, %08x, %08x)" % (address, size, alloc_type, protection))
        else:
            self.core_log("VirtualAllocEx(NULL, %d, %08x, %08x)" % (size, alloc_type, protection))

        allocated_address = kernel32.VirtualAllocEx(self.h_process, address, size, alloc_type, protection)

        if not allocated_address:
            raise pdx("VirtualAllocEx(%08x, %d, %08x, %08x)" % (address, size, alloc_type, protection), True)

        return allocated_address


    ####################################################################################################################
    def virtual_free (self, address, size, free_type):
        '''
        Convenience wrapper around VirtualFreeEx()

        @type  address:    DWORD
        @param address:    Pointer to the starting address of the region of memory to be freed
        @type  size:       Integer
        @param size:       Size of memory region to free, in bytes
        @type  free_type:  DWORD
        @param free_type:  The type of free operation

        @raise pdx: An exception is raised on failure.
        '''

        self.core_log("VirtualFreeEx(%08x, %d, %08x)" % (address, size, free_type))

        if not kernel32.VirtualFreeEx(self.h_process, address, size, free_type):
            raise pdx("VirtualFreeEx(%08x, %d, %08x)" % (address, size, free_type), True)


    ####################################################################################################################
    def virtual_protect (self, base_address, size, protection):
        '''
        Convenience wrapper around VirtualProtectEx()

        @type  base_address: DWORD
        @param base_address: Base address of region of pages whose access protection attributes are to be changed
        @type  size:         Integer
        @param size:         Size of the region whose access protection attributes are to be changed
        @type  protection:   DWORD
        @param protection:   Memory protection to apply to the specified region

        @raise pdx: An exception is raised on failure.
        @rtype:     DWORD
        @return:    Previous access protection.
        '''

        self.core_log("VirtualProtectEx( , 0x%08x, %d, %08x, ,)" % (base_address, size, protection))

        old_protect = c_ulong(0)

        if not kernel32.VirtualProtectEx(self.h_process, base_address, size, protection, byref(old_protect)):
            raise pdx("VirtualProtectEx(%08x, %d, %08x)" % (base_address, size, protection), True)

        return old_protect.value


    ####################################################################################################################
    def virtual_query (self, address):
        '''
        Convenience wrapper around VirtualQueryEx().

        @type  address: DWORD
        @param address: Address to query

        @raise pdx: An exception is raised on failure.

        @rtype:  MEMORY_BASIC_INFORMATION
        @return: MEMORY_BASIC_INFORMATION
        '''

        mbi = MEMORY_BASIC_INFORMATION()

        if kernel32.VirtualQueryEx(self.h_process, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            raise pdx("VirtualQueryEx(%08x)" % address, True)

        return mbi


    ####################################################################################################################
    def win32_error (self, prefix=None):
        '''
        Convenience wrapper around GetLastError() and FormatMessage(). Raises an exception with the relevant error code
        and formatted message.

        @type  prefix: String
        @param prefix: (Optional) String to prefix error message with.

        @raise pdx: An exception is always raised by this routine.
        '''

        error      = c_char_p()
        error_code = kernel32.GetLastError()

        kernel32.FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                                None,
                                error_code,
                                0x00000400,     # MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
                                byref(error),
                                0,
                                None)
        if prefix:
            error_message = "%s: %s" % (prefix, error.value)
        else:
            error_message = "GetLastError(): %s" % error.value

        raise pdx(error_message, error_code)


    ####################################################################################################################
    def write (self, address, data, length=0):
        '''
        Alias to write_process_memory().

        @see: write_process_memory
        '''

        return self.write_process_memory(address, data, length)


    ####################################################################################################################
    def write_msr (self, address, data):
        '''
        Write data to the specified MSR address.

        @see: read_msr

        @type  address: DWORD
        @param address: MSR address to write to.
        @type  data:    QWORD
        @param data:    Data to write to MSR address.

        @rtype:  tuple
        @return: (read status, msr structure)
        '''

        msr         = SYSDBG_MSR()
        msr.Address = address
        msr.Data    = data

        status = ntdll.NtSystemDebugControl(SysDbgWriteMsr,
                                            byref(msr),
                                            sizeof(SYSDBG_MSR),
                                            0,
                                            0,
                                            0);

        return status


    ####################################################################################################################
    def write_process_memory (self, address, data, length=0):
        '''
        Write to the debuggee process space. Convenience wrapper around WriteProcessMemory(). This routine will
        continuously attempt to write the data requested until it is complete.

        @type  address: DWORD
        @param address: Address to write to
        @type  data:    Raw Bytes
        @param data:    Data to write
        @type  length:  DWORD
        @param length:  (Optional, Def:len(data)) Length of data, in bytes, to write

        @raise pdx: An exception is raised on failure.
        '''

        count = c_ulong(0)

        # if the optional data length parameter was omitted, calculate the length ourselves.
        if not length:
            length = len(data)

        # ensure we can write to the requested memory space.
        _address = address
        _length  = length
        try:
            old_protect = self.virtual_protect(_address, _length, PAGE_EXECUTE_READWRITE)
        except:
            pass

        while length:
            c_data = c_char_p(data[count.value:])

            if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
                raise pdx("WriteProcessMemory(%08x, xxx, %d)" % (address, length), True)

            length  -= count.value
            address += count.value

        # restore the original page permissions on the target memory region.
        try:
            self.virtual_protect(_address, _length, old_protect)
        except:
            pass