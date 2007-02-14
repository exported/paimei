#!/bin/sh

rm -f file_access_tracker.py
rm -f stack_integrity_monitor.py
rm -f struct_spy.py
rm -f pydbg_server.py
rm -f var_backtrace.py
rm -f demo_live_graphing.py
rm -f pydbg/pydbg_client.py
rm -f ollydbg_connector/paimei_ollydbg_connector.ncb
mv pydbg/pydbg_client_public_release.py pydbg/pydbg_client.py

rm -rf deprecated
rm -rf fuzz_assist
rm -rf docs/PAIMEIpstalker_flash_demo

find ./ -name .svn -exec rm -rf {} \;

./__build_installer.bat
./__generate_epydocs.bat

mv dist/PaiMei-1.2.win32.exe installers

rm -rf build
rm -rf dist

find ./ -name \*.pyc -exec rm -f {} \;