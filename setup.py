#!c:\python\python.exe

from distutils.core import setup

setup( name         = "PaiMei",
       version      = "1.1",
       description  = "PaiMei - Reverse Engineering Framework",
       author       = "Pedram Amini",
       author_email = "pedram.amini@gmail.com",
       url          = "http://www.openrce.org",
       license      = "GPL",
       packages     = ["pida", "pgraph", "pydbg", "utils"],
       package_data = {"pydbg" : ["pydasm.pyd"]})