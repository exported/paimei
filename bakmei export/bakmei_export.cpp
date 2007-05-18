
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
 
#include <time.h>

#include "sqlite3.h"

#include "sqlite_syntax.hpp" 

void bakmei_export(void);

void select_database_type(char *);
sqlite3 * create_sqlite_storage(char *);

void enumerate_imports(int);
void enumerate_rpc(int);

char *sql_escape(char *);

int create_module(char*);
void create_function(func_t *, int);
void create_basic_block(ea_t, ea_t, int, int);
void create_instruction(ea_t, int, int, int);
void create_operands(int, ea_t);
void create_operand(int, ea_t, int);

sqlite3 *db_ptr;

int IDAP_init(void)
{
	// Do checks here to ensure the plug-in is being used within
	// an environment it was written for. Return PLUGIN_SKIP if the
	// checks fail, otherwise return PLUGIN_KEEP

	// TODO
	// In this case we'll be looking for IDA v5+
	return PLUGIN_KEEP;
}

void IDAP_term(void)
{
	// Stuff to do when exiting, clean up jobs go here

	// TODO : Cleanup Routines
	sqlite3_close(db_ptr);

	return;
}

// Eventually we'll have it choose which type of export based on the arg here
void IDAP_run(int arg)
{
	// Meat-o-licious
	bakmei_export();
}

char IDAP_comment[]		= "This is the Bak Mei export plugin.";
char IDAP_help[]		= "Bak Mei Exporter";

char IDAP_name[]		= "Bak Mei Exporter";

char IDAP_hotkey[]		= "Shift-Alt-B";

// The all-important exported PLUGIN object
plugin_t PLUGIN = 
{
	IDP_INTERFACE_VERSION,		// IDA version plug-in is written for
	0,							// Flags
	IDAP_init,					// Initialization function
	IDAP_term,					// Clean-up function
	IDAP_run,					// Main plug-in body
	IDAP_comment,				// Comment - unused
	IDAP_help,					// As above - unused
	IDAP_name,					// Name from the Edit menu
	IDAP_hotkey					// Hot key to run the plugin
};


void bakmei_export(void)
{
	time_t start_time, run_time;
	int module_id = 0;
	char input_file[400]; // Seriously, why 400? I'm a lazy f

	get_input_file_path(input_file, 400);
	select_database_type(input_file);

	msg("Analyzing IDB...\n");
	
	// Get Start Time
	time(&start_time);

	// Create Module
	
	module_id = create_module(input_file);

	// Generate Cross References

	// Set up Detailed Operands

	time(&run_time);


	msg("Done. Completed in %.2lf seconds.\n", difftime(run_time, start_time));
}

void select_database_type(char *input_filename)
{
	const char initial_format[] = 
		"STARTITEM 0\n"
		"HELP\n"
		"The text seen in the 'help window' when the\n"
		"user hits the 'Help' button.\n"
		"ENDHELP\n"

		"Choose the database engine for export.\n"					// Title
		
		 //  Radio Buttons
		"<#This will set the export engine to use SQLite.#"         // hint radio_sqlite
		"SQLite:R>\n"												// text radio_sqlite

		"<#This will set the export engine to use MySQL.#"          // hint radio_mysql
		"MySQL:R>>\n\n"												// text radio_mysql                     
		;

	const char mysql_format[] = 
		"STARTITEM 0\n"
		"HELP\n"
		"The text seen in the 'help window' when the\n"
		"user hits the 'Help' button.\n"
		"ENDHELP\n"

		"Choose the database engine for export.\n"					// Title
		"Select the database information for export.\n\n"           // Dialog Text
		"<Host:A:254:30:::>\n"
		"<Username:A:254:30:::>\n"
		"<Password:A:254:30:::>\n\n"
		; // End Dialog Format String

	short db_format = 0;
	
	int ok = AskUsingForm_c(initial_format, &db_format);
	
	switch(db_format)
	{
		case 0:
			// SQLite
			db_ptr = create_sqlite_storage(input_filename);
			
			break;
		case 1:
			// MySQL
			char hostname[255] = "";
			char username[255] = "";
			char password[255] = "";

			break;
	}

	return;
}

int schema_check_callback(void *counter, int num_fields, char **fields, char **col_names)
{
	// We only need to know *if* this function is hit, not really the contents
	*(int *)counter += 1;

	return 0;
}

sqlite3 * create_sqlite_storage(char *input_filename)
{
	char *filename = NULL, *suggested_file = NULL;
	int suggested_file_length = 0;
	sqlite3 *ret_val = NULL;
	
	filename = strrchr(input_filename, '\\') + 1;
	suggested_file_length = strlen(filename) + 5;
	suggested_file = (char *) malloc(suggested_file_length);

	strcpy_s(suggested_file, suggested_file_length, filename);
	strncat_s(suggested_file, suggested_file_length, ".obd", 4);

	// Where would this filename memory get cleared?
	filename = askfile_c(1, suggested_file, "Select the filename to be exported to.");
	
	free(suggested_file);

	if (NULL != filename)
	{
		struct _stat buf;

		// Check for database existence
		if (_stat(filename, &buf) == 0)
		{
			int overwrite = askbuttons_c("Overwrite", "Insert Into Exisiting", "Cancel", 1, "TITLE File Exists\n"
				"ICON QUESTION\n"
				"AUTOHIDE NONE\n"
				"The file %s already exists, would you like to overwrite?", filename);
			if ( -1 == overwrite)
				return NULL;
			else if (1 == overwrite)
			{
				remove(filename);
			}
		}

		// TODO : export from memory when done
		// Open SQL database
		sqlite3_open(":memory:"/*filename*/, &ret_val);

		
		// Test for schema
		int table_count = 0;
		sqlite3_exec(ret_val, "SELECT name FROM sqlite_master WHERE type='table';", &schema_check_callback, &table_count, NULL);

		if (table_count <= 0)
		{
			for (int i = 0; i < 16; i++)
			{
				sqlite3_exec(ret_val, SQLITE_CREATE_BAKMEI_SCHEMA[i], NULL, NULL, NULL);
			}
		}
		else
		{
			if (table_count != 16)
			{
				msg("We might have problems, there were %d tables in the database\n", table_count);
			}
		}
	}

	return ret_val;
}

/*
	It is expected that the input file as passed in includes all path separators.
	At the moment, I will only parse by '\' as portability isn't my biggest concern.
*/
int create_module(char *input_file)
{
	int module_id = 0;
	char *module_name;
	struct _stat buf;
	ea_t base_address = 0;
	

	// Check to see if the original file is still where it was when the IDB was generated.
	// fileAttr = GetFileAttributes(input_file);
	if (_stat(input_file, &buf) == 0)
	{
		//TODO
		// Generate Signature
		msg("[-] pretending to generate sig\n");
	}
	else
	{
		// No signature to generate - blank string
		msg("[-] pretending to not generate sig\n");
	}

	module_name = strrchr(input_file, '\\') + 1; // increment to skip slash 
	base_address = inf.minEA - 0x1000;

	// Generate SQL INSERT statement
	char * safe_module_name = sql_escape(module_name);
	
	int sql_size = strlen(INSERT_MODULE) + strlen(safe_module_name) + 10 /* max address size */ + 255 /* max version size */ +1 /*Z*/;
	char *sql = (char *) malloc(sql_size);
	sprintf_s(sql, sql_size, INSERT_MODULE, safe_module_name, base_address, "'0'");
	free(safe_module_name); // Done with this, clean it up.

	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
	module_id = sqlite3_last_insert_rowid(db_ptr);
 
	if (errmsg != NULL)
	{
		msg("Error %s", errmsg);
		sqlite3_free(errmsg);
		return 0;
	}

	func_t *current_function;
	float last_pct = .1, fns = 0, func_count = get_func_qty();

	msg("Exporting %f functions.. \n", func_count);
	for (fns = 0; fns < func_count; fns++)
	{
		current_function = getn_func(fns);
	    create_function(current_function, module_id);
		
		// Display progress every 10 percent
		if (fns/func_count > last_pct)
		{
			last_pct += .1;
			msg("%0.00f%% Completed...\n", last_pct * 100);
		}
	}

    enumerate_imports(module_id);

	enumerate_rpc(module_id);

	return module_id;
}

char *sql_escape(char *source)
{
	int quote_counter = -1;
	char *temp = source-1;

	do
	{		
		temp++;
		temp = strchr(temp, '\'');
				
		quote_counter++;		
	} while(temp != NULL);
	
	char * ret_val = (char *) malloc(strlen(source) 
									+ 2 /*outer*/ 
									+ quote_counter /*inner*/ 
									+ 1 /*Z*/);
	
	char *src = source, *dst = ret_val, lastchar;
	dst[0] = '\'';
	dst++;
	do
	{
		lastchar = *src;
		*dst = lastchar;
		src++;
		dst++;
		if (lastchar == '\'')
		{
			*dst = '\'';
			dst++;
		}	
		
	}while (*src != '\0');

	*dst = '\'';
	*(dst+1) = '\0';
 
	return ret_val;
}

void create_function(func_t *current_function, int module_id)
{
	int function_id = 0;
	char function_name[256];
	
	function_name[255] = 0; // Redundancy is better than not having redundancy
	char * safe_fn_name = sql_escape(get_func_name(current_function->startEA, function_name, 255));

	int sql_size = strlen(INSERT_FUNCTION) 
					+ strlen(safe_fn_name) 
					+ 10 /* max module id size */
					+ 10 /* max start address size */ 
					+ 10 /* max end address size */
					+ 1 /*Z*/;

	char *sql = (char *) malloc(sql_size);

	sprintf_s(sql, sql_size, INSERT_FUNCTION, module_id, current_function->startEA, prev_not_tail(current_function->endEA), safe_fn_name);
	free(safe_fn_name); // Done with this, clean it up.

	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
	function_id = sqlite3_last_insert_rowid(db_ptr);
 	 
	//flags = current_function->flags; // this is stupid to variablize
	//TODO: flags should have been inserted at begin

	if (NULL == current_function)
		throw "fuck";

	int frame_size = 0, saved_reg_size = 0, local_var_size = 0;

	/* Sort out Frame Info later TODO
    saved_reg_size = current_function->frregs;
    frame_size     = current_function->frsize;
	// TODO : what is this actually? Also, should local var size == frame size?
    //ret_size       = get_frame_retsize(current_function);
    local_var_size = current_function->frsize;

    // curs.execute(INSERT_FRAME_INFO % (dbid, saved_reg_size, frame_size, ret_size, local_var_size))
	*/

    //TODO init_args_and_local_vars(func_struct, frame_struct, dbid, module_id)

	int *chunks = NULL;
	
    func_tail_iterator_t *iterator = new func_tail_iterator_t(current_function);

    bool status = iterator->main();

    while (NULL != status)
	{
        area_t chunk = iterator->chunk();
    
		ea_t addr = next_not_tail(chunk.startEA);

		ea_t block_start = chunk.startEA;

		// enumerate the nodes.
		while (addr < chunk.endEA)
		{			
            // ignore data heads.
            if (isCode(getFlags(addr)))
			{	             
				ea_t prev_ea       = prev_not_tail(addr);
				ea_t next_ea       = next_not_tail(addr);

				// ensure that both prev_ea and next_ea reference code and not data.
				// TODO : Why does this call prev_not_tail twice? This code doesn't even make sense. cjh
				while (!isCode(getFlags(prev_ea)))
					prev_ea = prev_not_tail(prev_ea);

				while (!isCode(getFlags(next_ea)))
					next_ea = prev_not_tail(next_ea);

				// TODO: Currently CALLs are (sometimes??) terminating basic blocks.. is this the behavior we want?

				// if the current instruction is a ret instruction, end the current node at ea.
				// if there is a branch from the current instruction, end the current node at ea.
				if (is_ret_insn(addr) || get_next_cref_from(addr, get_first_cref_from(addr)) != BADADDR || chunk.endEA == next_ea)
				{
					create_basic_block(block_start, addr, function_id, module_id);

					// start a new block at the next ea.
					block_start = next_ea;
				}
				// if there is a branch to the current instruction, end the current node at previous ea.
				else if (get_next_cref_to(addr, get_first_cref_to(addr)) != BADADDR && block_start != addr)
				{
					create_basic_block(block_start, prev_ea, function_id, module_id);
					// start a new block at ea.
					block_start = addr;
				}
			}

			addr = next_not_tail(addr);		
		}

		status = iterator->next();
	}
            
    return;
}

void create_basic_block(ea_t starting_address, ea_t ending_address, int function_id, int module_id)
{
	int basic_block_id = 0;

	int sql_size = strlen(INSERT_BASIC_BLOCK) 					
					+ 10 /* max start address size */ 
					+ 10 /* max end address size */
					+ 10 /* max function id size */
					+ 10 /* max module id size */
					+ 1 /*Z*/;

	char *sql = (char *) malloc(sql_size);

	sprintf_s(sql, sql_size, INSERT_BASIC_BLOCK, starting_address, ending_address, function_id, module_id);
	
	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
	basic_block_id = sqlite3_last_insert_rowid(db_ptr);
	
	ea_t addr = next_not_tail(starting_address-1);

	// enumerate the nodes.
	while (addr <= ending_address)
	{			
		if (!isCode(getFlags(addr)))
		{
			msg("0x%08x: Fucked up.. this isn't an instruction..\n", addr);
			return;
		}
		create_instruction(addr, basic_block_id, function_id, module_id);
		addr = next_not_tail(addr);		
	}
	return;
}

void create_instruction(ea_t address, int basic_block_id, int function_id, int module_id)
{
	ea_t end_address = get_item_end(address);
	char comment[256] ; // Default max, if exceeded, create a dynamic routine.
	int comment_size = 0;
	int instruction_id = 0;

	int instruction_length = end_address - address;
	unsigned char bytes[20]; // Max Size in the database

	// Get the raw bytes
	for (int counter = 0; (address + counter) < end_address; counter++)
	{
		bytes[counter] = get_byte(address+counter);
		// TODO: may be best to convert to the string form here.

		if (counter > 20)
		{
			msg("0x%08x: Check instruction here for long bytes\n", address);
		}
	}

	comment_size = get_cmt(address, 0, comment, 255);

	if (comment_size >= 255)
	{
		msg("Default comment size exceeded!\n");
	}
	else if (comment_size > 0)
	{
		//TODO: Insert Comment into database
	}
	
	char mnem[16];
	mnem[15] = 0;
	ua_mnem(address, mnem, 15);

	// INSERT address, basic_block_id, function_id, mnemonic
	char * safe_mnem = sql_escape(mnem);

	int sql_size = strlen(INSERT_INSTRUCTION) 
					+ strlen(safe_mnem)
					+ 10 /* max address size */
					+ 10 /* max module id size */
					+ 10 /* max function idsize */ 
					+ 10 /* max basic_block_id size */
					+ 20 /* max bytes size ?? escape later */
					+ 1 /*Z*/;

	char *sql = (char *) malloc(sql_size);
		
	sprintf_s(sql, sql_size, INSERT_INSTRUCTION, address, basic_block_id, function_id, module_id, safe_mnem, "'FFFF'");
	free(safe_mnem); // Done with this, clean it up.

	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
	instruction_id = sqlite3_last_insert_rowid(db_ptr);

	// TODO
	// instruction_address_lookup[ea] = (dbid, block_id, function_id)

	create_operands(instruction_id, address);

	return;
}

void create_operands(int instruction_id, ea_t address)
{
	int opnum = 0;
	char op_buf[4]; // this isn't actually used, just to check existence

	for (opnum = 0; opnum < 3; opnum++)
	{
		if (ua_outop(address, op_buf, 4, opnum))
			create_operand(instruction_id, address, opnum);
		else
			return;
	}

	return;
}

void create_operand(int instruction_id, ea_t address, int opnum)
{
	char op[256];
	int operand_id = 0;

	// Set op to string representation of operand
	ua_outop(address, op, 256, opnum);

	// Insert into database
	char * safe_oper = sql_escape(op);

	int sql_size = strlen(INSERT_OPERAND) 
					+ strlen(safe_oper)
					+ 10 /* max instruction id size */
					+ 10 /* max oper seq size */
					+ 1 /*Z*/;

	char *sql = (char *) malloc(sql_size);
		
	sprintf_s(sql, sql_size, INSERT_OPERAND, instruction_id, opnum, safe_oper);
	free(safe_oper); // Done with this, clean it up.

	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
	operand_id = sqlite3_last_insert_rowid(db_ptr);
  	
  	    //op_type = GetOpType(ea, position)
  	
	ua_ana0(address);
	op_t ida_op = cmd.Operands[opnum];
  	
  	int index = 0;
  	
	// TODO
	//op_width = OPERAND_WIDTH[ord(ida_op.dtyp)][1]
  	
  	//root = create_expression_entry(NODE_TYPE_OPERATOR_ID, op_width, None, 0, None)
 	//root[0] = 0
  	
  	//tree = [root]
  	
  	/*    if op_width[1] == "":
  	        raise NotImplementedError, "Missing operand width for %s" % op_width[0]
  	*/
	switch (ida_op.type)
	{
	case o_reg:
    
        // General Register
        // tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, op, None, 1, 0))
		break;
    case o_mem:
        // Memory Reference
        // create_memory_reference_operand(tree, ida_op, op, ea)
		break;
	case o_phrase:
        // Phrase (Base + Index)
        // create_phrase_operand(tree, ida_op, op, ea)
		break;
	case o_displ:
		// (+) Displacement
        // create_displ_operand(tree, ida_op, op, ea)
		break;
	case o_imm:
        // Immediate
        // TODO: String references aren't being saved.. Fix this
        tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, GetOperandValue(address, position), 1, 0))
		break;
	case o_far:
	case o_near:
        // Immediate (Far, Near) Address
        // TODO: save substitution of ptr addresses
        tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr,  1, 0))
		break;
	case o_idpspec3:
        // 386 Trace Register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, 'st(%d)' % ida_op.reg, None, 1, 0));
		break;    
	case o_idpspec4:
        // MMX register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, 'mm%d' % ida_op.reg, None, 1, 0));
		break;    
	case o_idpspec5:
        // XMM register
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, 'xmm%d' % ida_op.reg, None, 1, 0))
    default:
        print "0x%08x: Gonna die..." % ea
        raise NotImplementedError, "Currently can not process %d operands" % op_type

    if len(tree) == 1:
        print "0x%08x: Gonna die..." % ea
        raise NotImplementedError, "No operands for %d operands" % op_type

    // TODO Insert into database
    INSERT_EXPRESSION = "INSERT INTO expression (expr_type, symbol, immediate, position, parent_id) VALUES (%d, %s, %s, %d, %s)"

    parent_lookup = {}
    for entry in tree:
   
        tmp_symbol = "NULL"
        if entry[2]:
            tmp_symbol = ss.sql_safe_str(entry[2])
        tmp_immediate = "NULL"
        if entry[3]:
            tmp_immediate = entry[3]
        tmp_parent = "NULL"
        if entry[5]:
            tmp_parent = parent_lookup[entry[5]]
           
        sql = INSERT_EXPRESSION % (entry[1], tmp_symbol, tmp_immediate, entry[4], tmp_parent)
        curs.execute(sql)
        expr_id = curs.lastrowid
        parent_lookup[entry[0]] = expr_id
 
        // TODO : now might be a good time to eliminate dupes
  	
}

void enumerate_imports(int module_id)
{
	msg("Enumerating imports...\n");
}

void enumerate_rpc(int module_id)
{
	msg("Enumerating RPC functions...\n");
}