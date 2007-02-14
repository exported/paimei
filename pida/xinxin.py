# Todo
# [ ] Do file type auto detection (Module.initFromFile)
#     [ ] PE
#     [ ] MZ
#     [ ] elf
#     [ ] ...

from pysqlite2 import dbapi2

from pydbg import pydasm

class CodeDB:
    def __init__(self, filename):
        self.con = dbapi2.Connection(filename)
        self.createMissingTables()

    def createMissingTables(self):
        cur = self.con.cursor()
        if not self.hasTable('modules'):
            cur.execute("""
                    create table modules (
                            id integer primary key,
                            name text,
                            srcfile text,
                            entry integer,
                            comment text)""")

        if not self.hasTable('sections'):
            cur.execute("""
                    create table sections (
                            moduleid integer key,
                            name text,
                            start integer,
                            type integer,
                            bytes blob)""")
        if not self.hasTable('functions'):
            cur.execute("""
                    create table functions (
                            id integer primary key,
                            moduleid integer key,
                            name text,
                            entry integer,
                            start integer,
                            end integer,
                            comment text)""")
        if not self.hasTable('calls'):
            cur.execute("""
                    create table calls (
                            id integer primary key,
                            moduleid integer key,
                            from_function integer,
                            to_function integer)""")

        if not self.hasTable('blocks'):
            cur.execute("""
                    create table blocks (
                            id integer primary key,
                            moduleid integer key,
                            functionid integer key,
                            comment text,
                            entry integer,
                            bytes blob)""")

        if not self.hasTable('jumps'):
            cur.execute("""
                    create table jumps (
                            id integer primary key,
                            moduleid integer key,
                            functionid integer key,
                            fromblock integer,
                            toblock integer)""")
        self.con.commit()
        cur.close()

    def hasTable(self, name):
        cur = self.con.cursor()
        cur.execute('select * from sqlite_master where (type = ?) and (name = ?)',('table',name))
        try:
            cur.next()
            # not sure if close() is needed
            cur.close()
            return 1
        except:
            # not sure if close() is needed
            cur.close()
            return 0

    def doInsert(self, sql, values):
        cur = self.con.cursor()
        cur.execute(sql, values)
        id = cur.lastrowid
        self.con.commit()
        cur.close()
        return id
     
    def addModule(self, name, srcfile):
        # creates a module and returns its id (if it doesn't exists)
        module = None
        try:
            module = self.getModule(name)
        except:
            pass
        
        if module:
            raise Exception('Duplicated module %s' % name)

        return self.doInsert('insert into modules (id,name,srcfile) values (?,?,?)',(None,name,srcfile))

    def getModule(self, name):
        module = Module(self)
        self.initModule(module, name)
        return module

    def initModule(self, module, name):
        cur = self.con.cursor()
        cur.execute('select id, srcfile from modules where name = ?', (name,))
        id, srcfile = cur.next()
        module.id = id
        module.srcfile = srcfile
        cur.close()

    def __fini__(self):
        # not sure if close() is needed
        self.con.close()

class Module:
    def __init__(self, db, name = None, srcfile = None):
        """
        db must be a CodeDB
        name is the name of the module. Don't needed if srcfile is specified. needed to load from db
        srcfile is a file name. Specify if you want to disassemble.
        """

        self.db = db
        self.isFromFile = False
        if srcfile:
            self.initFromFile(name, srcfile)
        elif name:
            self.initFromDB(name)

    def initFromDB(self, name):
        self.db.initModule(self, name)

    def initFromFile(self, name, srcfile):
        self.isFromFile = True
        if not name:
            name = srcfile

        self.id = self.db.addModule(name, srcfile)
        self.name = name
        self.srcfile = srcfile

        # XXX: do some file type detection
        self.loadPE()

    def loadPE(self):
        # will load self.srcfile as a PE
        import pefile

        pe = pefile.PE(srcfile)
        base = pe.OPTIONAL_HEADER.ImageBase
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint + base
        for section in self.sections:
            
        # XXX: self.image = pe.get_memory_mapped_image()
        
    def analyze(self):
        pass
    
if __name__ == '__main__':
    db = CodeDB('code.db')
    try:
        m = Module(db, srcfile = r'\winnt\system32\winmine.exe')
        m.analyze()
        print m.id
    except:
        db.con.close()
        raise
    db.con.close()