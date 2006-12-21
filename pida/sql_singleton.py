import MySQLdb
from pysqlite2 import dbapi2 as sqlite
from sqlite_queries import *

class sql_singleton:
    '''
     A singleton used to store the SQL connection 
    '''


    # storage for the instance reference
    __instance = None    

    class __impl:
        '''
        Implementation of the singleton interface 
        '''        

        # storage for the instance connection    
        __sql               = {}
        __active_playground = None
        __active_syntax     = "sqlite"
          
        INSERT_INSTRUCTION          = cINSERT_INSTRUCTION
        INSERT_MODULE               = cINSERT_MODULE
        INSERT_BASIC_BLOCK          = cINSERT_BASIC_BLOCK
        INSERT_FUNCTION             = cINSERT_FUNCTION
        UPDATE_INSTRUCTION_COMMENT  = cUPDATE_INSTRUCTION_COMMENT
        UPDATE_INSTRUCTION_OPERAND1 = cUPDATE_INSTRUCTION_OPERAND1
        UPDATE_INSTRUCTION_OPERAND2 = cUPDATE_INSTRUCTION_OPERAND2
        UPDATE_INSTRUCTION_OPERAND3 = cUPDATE_INSTRUCTION_OPERAND3
        UPDATE_INSTRUCTION_FLAGS   = cUPDATE_INSTRUCTION_FLAGS
        
        UPDATE_FUNCTION_FLAGS = cUPDATE_FUNCTION_FLAGS
        UPDATE_FUNCTION_ARG_SIZE = cUPDATE_FUNCTION_ARG_SIZE
        
        def connection(self, playground=None):
            '''
            return the SQL connection object
            '''
            
            if playground == None:
                playground = self.__active_playground
            
            if not self.__sql.has_key(playground):
                self.__init_connection(playground)
            
            return self.__sql[playground]
            
        def __init_connection(self, playground_name):   
            
            if self.__active_syntax == "mysql":
                try:
                    self.__sql[playground_name] = MySQLdb.connect(host=host, user=username, passwd=password, db="pida_" + playground_name)
                except MySQLdb.OperationalError, err:
                    if err[0] == 1049:
                        # DB doesn't exist, let's make it!
                        create_pida_database(playground_name)
                    else:
                        raise MySQLdb.OperationalError, err
            else: 
                #sqlite
                self.__sql[playground_name] = sqlite.connect(playground_name)
                
                tables =  self.__sql[playground_name].cursor().execute("SELECT name from sqlite_master where type='table';")
                
                if len(tables.fetchall()) == 0:
                    self.create_pida_database(playground_name)
            
            
            self.__active_playground = playground_name  #TEMP

        def create_pida_database(self, playground):
            #self.__sql[playground] = MySQLdb.connect(host=host, user=username, passwd=password)
            #cursor = self.__sql[playground].cursor()
            #
            ## create db
            #cursor.execute("CREATE DATABASE pida_" + playground)
            #cursor.execute("USE pida_" + playground)
            #
            ## create tables
            #for query in MYSQL_CREATE_PIDA_SCHEMA:
            #    cursor.execute(query)
            cursor = self.__sql[playground].cursor()
            
            for query in SQLITE_CREATE_PIDA_SCHEMA:
                cursor.execute(query)
                
            self.__sql[playground].commit()
            
        def cursor(self):
            return self.__sql[self.__active_playground].cursor()
        
        
    def __init__(self):
        '''
        Create singleton instance
        '''
        # Check whether we already have an instance
        if sql_singleton.__instance is None:
            # Create and remember instance
            sql_singleton.__instance = sql_singleton.__impl()

        # Store instance reference as the only member in the handle
        self.__dict__['_sql_singleton__instance'] = sql_singleton.__instance

    def __getattr__(self, attr):
        '''
        Delegate access to implementation
        '''
        return getattr(self.__instance, attr)

    def __setattr__(self, attr, value):
        '''
        Delegate access to implementation
        '''
        return setattr(self.__instance, attr, value)
    