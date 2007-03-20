# $Id$

from module      import module

__all__ = \
[
    "basic_block",
    "defines",
    "function",
    "instruction",
    "operand",
    "module",
    "sql_singleton",
    "sqlite_queries",
    "mysql_queries"
]


########################################################################################################################
def load (file_name, progress_bar=None):
    '''
    Restore a saved BAKMEI module from disk.

    @type  file_name: String
    @param file_name: File name to import from
    @type  progress_bar: String
    @param progress_bar: (Optional, Def=None) Can be one of "wx", "ascii" or None

    @rtype:  Mixed
    @return: Imported module on success, 0 on cancel and -1 on failure.
    '''

    if progress_bar:
        progress_bar = progress_bar.lower()

    return module(file_name)

########################################################################################################################
def signature (file_name):
    '''
    Create and return a signature (hash) for the specified file.

    @todo: Look into replacing this with something faster.

    @type  file_name: String
    @param file_name: File name to import from

    @rtype:  String
    @return: 32 character MD5 hex string
    '''

    try:
        fh = open(file_name, "rb")
    except:
        # try this on for size.
        fh = open("c:" + file_name, "rb")

    m  = md5.new()

    m.update(fh.read())

    return m.hexdigest()
