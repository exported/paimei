#!c:\python\python.exe

import cPickle
from pydbg import *
from pydbg.defines import *

class snippet_struct:
    def __init__ (self):
        self.address = None
        self.raw     = None
        self.handle  = None

class mem_bp_hit_struct (memory_breakpoint):
    def __init__ (self):
        self.disasm            = None
        self.write_violation   = None
        self.context           = None
        self.violation_address = None
        self.exception_address = None


fh = open("mem_bp_hits.pickle")
mem_bp_hits = cPickle.load(fh)
fh.close()

fh = open("snippets.pickle")
snippets = cPickle.load(fh)
fh.close()


violations = {}
for mbh in mem_bp_hits:
    if not violations.has_key(mbh.violation_address):
        violations[mbh.violation_address] = []

    violations[mbh.violation_address].append((mbh.exception_address, mbh.write_violation))


for va in violations.keys():
    fh = open("output/%08x.html" % va, "w+")
    fh.write("<center><table border=0 cellpadding=0 cellspacing=0><tr><td>\n")
    fh.write("<b>%d violations</b><br>" % len(violations[va]))
    fh.write("<pre>\n")

    for (exception_address, write_violation) in violations[va]:
        if write_violation:
            fh.write("%08x on write\n" % exception_address)
        else:
            fh.write("%08x on read\n" % exception_address)

    fh.write("</pre>\n")
    fh.write("</td></tr></table></center>")
    fh.close()


fh = open("output/index.html", "w+")
fh.write("""
<html>
<style>
    a:link    {color: #FF0000; font-weight: bold; text-decoration: none;}
    a:visited {color: #FF0000; font-weight: bold; text-decoration: none;}
    a:hover   {color: #FFFFFF; font-weight: bold; text-decoration: none; background-color: #FF0000}
    a:active  {color: #FF0000; font-weight: bold; text-decoration: none;}
</style>
<body bgcolor=#EBEBEB marginheight=0 leftmargin=0 topmargin=0 marginwidth=0 text=#000000>
<center><table border=0 cellpadding=20 cellspacing=0><tr><td bgcolor=#FFFFFF>
""")

for snippet in snippets:
    fh.write("<b>%08x</b> size:<b>%d</b>" % (snippet.address, len(snippet.raw)))
    fh.write("<pre>")
    addr = snippet.address
    slice = []

    remainder = addr % 16
    
    if remainder != 0:
        prefix = "\x00" * remainder
        snippet.raw = prefix + snippet.raw
        addr -= remainder

    for byte in snippet.raw:
        if addr % 16 == 0:
            fh.write(" ")

            for (_byte, _addr, _hits) in slice:
                if _addr and _hits:
                    fh.write("<acronym title=\"%08x: %d violations\"><a href=%08x.html>" % (_addr, _hits, _addr))
                
                if ord(_byte) >= 32 and ord(_byte) <= 126:
                    if _byte == ">":
                        fh.write("&gt;")
                    elif _byte == "<":
                        fh.write("&lt;")
                    else:
                        fh.write(_byte)
                else:
                    fh.write(".")

                if _addr and _hits:
                    fh.write("</a></acronym>")

            fh.write("\n%08x: " % addr)
            slice = []

        if violations.has_key(addr):
            fh.write("<acronym title=\"%08x: %d violations\"><a href=%08x.html>%02x</a></acronym> " % (addr, len(violations[addr]), addr, ord(byte), ))
            slice.append((byte, addr, len(violations[addr])))
        else:
            fh.write("%02x " % ord(byte))
            slice.append((byte, None, None))

        addr += 1

    remainder = addr % 16

    if remainder != 0:
        fh.write("   " * (16 - remainder) + " ")

        for (_byte, _addr, _hits) in slice:
            if _addr and _hits:
                fh.write("<acronym title=\"%08x: %d violations\"><a href=%08x.html>" % (_addr, _hits, _addr))
            
            if ord(_byte) >= 32 and ord(_byte) <= 126:
                if _byte == ">":
                    fh.write("&gt;")
                elif _byte == "<":
                    fh.write("&lt;")
                else:
                    fh.write(_byte)
            else:
                fh.write(".")

            if _addr and _hits:
                fh.write("</a></acronym>")

    fh.write("</pre><hr>\n")

fh.write("""
</td></tr></table></center>
</body>
</html>
""")
fh.close()