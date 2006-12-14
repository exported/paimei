SQLITE_CREATE_PIDA_SCHEMA = ("""
    CREATE TABLE module (
        id              INTEGER PRIMARY KEY,
        name            varchar(255) NOT NULL,
        base            int UNSIGNED NOT NULL,
        signature       text default '',
        data            blob,
        version         varchar(255) NOT NULL
        )""", """
        
    CREATE TABLE comments (
        id              INTEGER PRIMARY KEY,
        comment         text NOT NULL,
        next            int UNSIGNED
        )""","""
        
    CREATE TABLE function (
        id              INTEGER PRIMARY KEY,
        module          int UNSIGNED NOT NULL,
        start_address   int UNSIGNED NOT NULL,
        end_address     int UNSIGNED NOT NULL,
        name            varchar(255) NOT NULL,
        import          int UNSIGNED,
        flags           int UNSIGNED,
        comment         int UNSIGNED
        )""","""
        
    CREATE TABLE frame_info (
        function        INTEGER PRIMARY KEY,
        saved_reg_size  smallint UNSIGNED,
        frame_size      smallint UNSIGNED,
        ret_size        smallint UNSIGNED,
        local_var_size  smallint UNSIGNED,
        arg_size        smallint UNSIGNED
        )""","""
        
    CREATE TABLE rpc_data (
        function        INTEGER PRIMARY KEY,
        module          int UNSIGNED NOT NULL,
        uuid            char(36) NOT NULL,
        opcode          int NOT NULL,
        idl             text
        )""","""
    
    CREATE TABLE import (
        id              INTEGER PRIMARY KEY,
        module          int UNSIGNED NOT NULL,
        name            varchar(255) NOT NULL,
        library         varchar(255) NOT NULL
        )""","""
        
    CREATE TABLE function_variables (
        id              INTEGER PRIMARY KEY,
        function        int UNSIGNED NOT NULL,
        module          int UNSIGNED NOT NULL,
        name            varchar(255) NOT NULL,
        data_type       varchar(255),
        flags           int UNSIGNED NOT NULL,
        comment         int UNSIGNED,
        offset          int NOT NULL
        )""","""
        
    CREATE TABLE basic_block (
        id              INTEGER PRIMARY KEY,
        start_address   int UNSIGNED NOT NULL,
        end_address     int UNSIGNED NOT NULL,
        function        int UNSIGNED NOT NULL,
        module          int UNSIGNED NOT NULL,
        comment         int UNSIGNED,
        contiguous      tinyint(1)
        )""","""
        
    CREATE TABLE instruction (
        id              INTEGER PRIMARY KEY,
        address         int UNSIGNED NOT NULL,
        basic_block     int UNSIGNED NOT NULL,
        function        int UNSIGNED NOT NULL,
        module          int UNSIGNED NOT NULL,
        comment         int UNSIGNED,
        bytes           char(10) NOT NULL,
        mnemonic        varchar(15) NOT NULL,
        operand1        varchar(255),
        operand2        varchar(255),
        operand3        varchar(255)
        )""","""
        
    CREATE TABLE cross_references (
        id              INTEGER PRIMARY KEY,
        source          int UNSIGNED,
        destination     int UNSIGNED,
        reference_type  int UNSIGNED
        )""","""
        
    CREATE TABLE data (
        id              INTEGER PRIMARY KEY,
        address         int UNSIGNED,
        data_type       int UNSIGNED,
        value           text
        )""")
        
cINSERT_INSTRUCTION  = "INSERT INTO instruction (address, basic_block, function, module, mnemonic, bytes) VALUES (%d, %d, %d, %d, '%s', '%s');"
cINSERT_MODULE       = "INSERT INTO module (name, base, version) VALUES ('%s', %d, '%s');"
cINSERT_FUNCTION     = "INSERT INTO function (module, start_address, end_address, name) VALUES (%d, %d, %d, '%s');"
cINSERT_BASIC_BLOCK  = "INSERT INTO basic_block (start_address, end_address, function, module) VALUES (%d, %d, %d, %d);"

### INSTRUCTION ###

cUPDATE_INSTRUCTION_COMMENT     = "UPDATE instruction SET comment='%s' WHERE id=%d;"
cUPDATE_INSTRUCTION_OPERAND1    = "UPDATE instruction SET operand1='%s' WHERE id=%d;"
cUPDATE_INSTRUCTION_OPERAND2    = "UPDATE instruction SET operand2='%s' WHERE id=%d;"
cUPDATE_INSTRUCTION_OPERAND3    = "UPDATE instruction SET operand3='%s' WHERE id=%d;"
cUPDATE_INSTRUCTION_FLAGS       = "UPDATE instruction SET flags=%d WHERE id = %d;"

### FUNCTION ###

cUPDATE_FUNCTION_FLAGS          = "UPDATE function SET flags=%d WHERE id=%d;"
cUPDATE_FUNCTION_ARG_SIZE       = "UPDATE frame_info SET arg_size=%d WHERE function=%d;"