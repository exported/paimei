char *SQLITE_CREATE_BAKMEI_SCHEMA[16] = {
	 "CREATE TABLE module ("
     "   id              INTEGER PRIMARY KEY,"
     "   name            varchar(255) NOT NULL,"
     "   base            int UNSIGNED NOT NULL,"
     "   signature       text default '',"
     "   version         varchar(255) NOT NULL,"
     "   comment         int UNSIGNED"
     "   )", 

     "CREATE TABLE sections ("
     "    id              INTEGER PRIMARY KEY,"
     "    module          INTEGER NOT NULL,"
     "    name            varchar(255),"
     "    start           INTEGER,"
     "    end             INTEGER,"
     "    type            INTEGER,"
     "    bytes           BLOB"
     "    )",
     
     "CREATE TABLE comments ("
     "    id              INTEGER PRIMARY KEY,        "
     "    parent          int UNSIGNED,"
     "    comment         text NOT NULL,"        
     "    author          VARCHAR(255)"
     "    )",
     
     "CREATE TABLE function ("
     "    id              INTEGER PRIMARY KEY,"
     "    module          int UNSIGNED NOT NULL,"
     "    start_address   int UNSIGNED NOT NULL,"
     "    end_address     int UNSIGNED NOT NULL,"
     "    name            varchar(255) NOT NULL,"
     "    exported        smallint UNSIGNED,"
     "    flags           int UNSIGNED,"
     "    comment         int UNSIGNED"
     "    )",
     
     "CREATE TABLE frame_info ("
     "    function        INTEGER PRIMARY KEY,"
     "    saved_reg_size  smallint UNSIGNED,"
     "    frame_size      smallint UNSIGNED,"
     "    ret_size        smallint UNSIGNED,"
     "    local_var_size  smallint UNSIGNED,"
     "    arg_size        smallint UNSIGNED"
     "    )",
     
     "CREATE TABLE rpc_data ("
     "    function        INTEGER PRIMARY KEY,"
     "    module          int UNSIGNED NOT NULL,"
     "    uuid            char(36) NOT NULL,"
     "    opcode          int NOT NULL,"
     "    idl             text"
     "    )",
     
     "CREATE TABLE import ("
     "    id              INTEGER PRIMARY KEY,"
     "    module          int UNSIGNED NOT NULL,"
     "    function        int UNSIGNED,"
     "    name            varchar(255) NOT NULL,"
     "    library         varchar(255) NOT NULL"
     "    )",
     
     "CREATE TABLE function_variables ("
     "    id              INTEGER PRIMARY KEY,"
     "    function        int UNSIGNED NOT NULL,"
     "    module          int UNSIGNED NOT NULL,"
     "    name            varchar(255) NOT NULL,"
     "    data_type       varchar(255),"
     "    flags           int UNSIGNED NOT NULL,"
     "    comment         int UNSIGNED,"
     "    offset          int NOT NULL"
     "    )",
     
     "CREATE TABLE basic_block ("
     "    id              INTEGER PRIMARY KEY,"
     "    start_address   int UNSIGNED NOT NULL,"
     "    end_address     int UNSIGNED NOT NULL,"
     "    function        int UNSIGNED NOT NULL,"
     "    module          int UNSIGNED NOT NULL,"
     "    name            VARCHAR(255),"
     "    size            INTEGER,"
     "    comment         int UNSIGNED"
     "    )",
     
     "CREATE TABLE instruction ("
     "    id              INTEGER PRIMARY KEY,"
     "    address         int UNSIGNED NOT NULL,"
     "    basic_block     int UNSIGNED NOT NULL,"
     "    function        int UNSIGNED NOT NULL,"
     "    module          int UNSIGNED NOT NULL,"
     "    comment         int UNSIGNED,"
     "    bytes           varchar(40) NOT NULL,"
     "    mnemonic        varchar(15) NOT NULL"
     "    )",
     
     "CREATE TABLE operand ("
     "    id              INTEGER PRIMARY KEY,"
     "    instruction     INTEGER NOT NULL,"
     "    position        INTEGER NOT NULL,"
     "    operand_text    TEXT"
     "    )",
     
     "CREATE TABLE operand_expression ("
     "    operand         INTEGER NOT NULL,"
     "    expression      INTEGER NOT NULL"
     "    )",
     
     "CREATE TABLE expression ("
     "    id              INTEGER PRIMARY KEY,"
     "    expr_type       INTEGER NOT NULL,"
     "    symbol          VARCHAR(255),"
     "    immediate       INTEGER,"
     "    position        INTEGER NOT NULL,"
     "    parent_id       INTEGER"
     "    ) ",
     
     "CREATE TABLE expression_substitutions ("
     "    instruction     INTEGER,"
     "    operand         INTEGER,"
     "    expression      INTEGER,"
     "    substitution    VARCHAR(255)"
     "    ) ",
     
     "CREATE TABLE cross_references ("
     "    id              INTEGER PRIMARY KEY,"
     "    source          int UNSIGNED,"
     "    destination     int UNSIGNED,"
     "    reference_type  int UNSIGNED"
     "    )",
     
     "CREATE TABLE data ("
     "    id              INTEGER PRIMARY KEY,"
     "    address         int UNSIGNED,"
     "    data_type       int UNSIGNED,"
     "    value           text"
     "    )"};

const char *INSERT_MODULE = "INSERT INTO module (name, base, version) VALUES (%s, %d, %s);";
const char *INSERT_FUNCTION = "INSERT INTO function (module, start_address, end_address, name) VALUES (%d, %d, %d, %s);";
const char *INSERT_BASIC_BLOCK = "INSERT INTO basic_block (start_address, end_address, function, module) VALUES (%d, %d, %d, %d);";
const char *INSERT_INSTRUCTION = "INSERT INTO instruction (address, basic_block, function, module, mnemonic, bytes) VALUES (%d, %d, %d, %d, %s, %s);";
const char *INSERT_OPERAND = "INSERT INTO operand (instruction, position, operand_text) VALUES (%d, %d, %s);";