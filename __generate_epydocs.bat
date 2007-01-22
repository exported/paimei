set PythonPath=C:\Python24

%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\PyDbg     -c blue -n "PyDbg - Python Win32 Debugger" --url "http://www.openrce.org" pydbg\defines.py pydbg\breakpoint.py pydbg\hardware_breakpoint.py pydbg\memory_breakpoint.py pydbg\memory_snapshot_block.py pydbg\memory_snapshot_context.py pydbg\my_ctypes.py pydbg\pdx.py pydbg\pydbg.py pydbg\pydbg_core.py pydbg\system_dll.py
%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\PIDA      -c blue -n "PIDA - Pedram's IDA"           --url "http://www.openrce.org" pida\__init__.py pida\instruction.py pida\basic_block.py pida\function.py pida\module.py pida\sql_singleton.py pida\defines.py
%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\pGRAPH    -c blue -n "pGRAPH - Pedram's Graphing"    --url "http://www.openrce.org" pgraph\cluster.py pgraph\edge.py pgraph\graph.py pgraph\node.py
%PythonPath%\python.exe %PythonPath%\Scripts\epydoc.py -o docs\Utilities -c blue -n "Utilities"                     --url "http://www.openrce.org" utils\code_coverage.py utils\crash_binning.py utils\process_stalker.py utils\udraw_connector.py
