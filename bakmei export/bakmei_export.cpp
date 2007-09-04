/**********************************************************************************************************************
 Bak Mei Exporter - Exports from IDA to the Pai Mei back end database format
 Copyright (C) 2007 Cameron Hotchkies <chotchkies@tippingpoint.com>

 $Id$

 This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
 License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
 version.

 This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
 Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
***********************************************************************************************************************/

// MySQL API will die without this include
#include <winsock2.h>

#include <mysql.h>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
 
#include <time.h>

#include "sqlite3.h"
#include "sqlite_syntax.hpp" 

#include <vector>
#include <map>
#include <algorithm>

using namespace std;

#pragma region CONSTANTS
#define MAX_INT_STRLEN			20		// A ULLONG in decimal is max 20 characters long
#define MAX_MYSQL_HOSTNAME		255		// If your hostname is bigger, you're probably an asshole.

// Export Options
#define ADVANCED_EXPORT			0x0001	// Advanced export means all of the instruction/operand details
#define DBTYPE_SQLITE			0x0100	// SQLite file on local system
#define DBTYPE_MYSQL			0x0200	// MySQL database over a network, FAR SLOWER

enum NODE_TYPE
{
	MNEMONIC = 0,
	SYMBOL = 1,
	IMMEDIATE_INT = 2,
	IMMEDIATE_FLOAT = 3,
	OPERATOR = 4
};
#pragma endregion

#pragma region structures
struct operand_leaf
{
	int operator_type;
	char symbol[256];
	long immediate;
	int position;
	int parent;
};

struct refpair_struct
{
	// This comparator is used in the map construct.
	bool operator<(refpair_struct sec)
	{
		return source < sec.source || (source == sec.source && dest < sec.dest);
	}

	// This is required for the find function
	bool operator==(refpair_struct sec)
	{
		return source == sec.source && dest == sec.dest;
	}

	int source;
	int dest;
};

struct mysql_data
{
	char hostname[MAX_MYSQL_HOSTNAME];
	char username[255];
	char password[255];
};

// This is required for the map comparator. If there's a better way, PLEASE tell me
struct refpair_struct_lt
{
	bool operator()(struct refpair_struct rp1, struct refpair_struct rp2)
	{
		return rp1 < rp2;
	}
};
#pragma endregion

#pragma region globals
map<refpair_struct, int, refpair_struct_lt> global_branches;
map<ea_t, int*> instruction_address_lookup;
sqlite3 *db_ptr;
#pragma endregion

#pragma region Function_Prototypes
void bakmei_export(void);

int select_options(char *, void **);
int create_sqlite_storage(char *, char **);
void export_database(int, void *);

void export_mysql_database(mysql_data *);
void export_sqlite_database(char *);

void enumerate_imports(int);
void enumerate_rpc(int);
void generate_cross_references(void);

char *sql_escape(char *);
int schema_check_callback(void *, int, char **, char **);
int schema_dump_callback(void *, int, char **, char **);


int create_module(char*);
void create_function(func_t *, int);
void create_basic_block(ea_t, ea_t, int, int);
void create_instruction(ea_t, int, int, int);
void create_operands(int, ea_t);
void create_operand(int, ea_t, int, bool advanced = false);

void create_memory_reference_operand(vector<operand_leaf> *, op_t, char *, ea_t);
void create_phrase_operand(vector<operand_leaf> *, op_t, char *, ea_t);
void create_displacement_operand(vector<operand_leaf> *, op_t, char *, ea_t);
#pragma endregion

#pragma region IDA_Specific
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

	msg("Finished\n");

	// TODO : Cleanup Routines
	sqlite3_close(db_ptr);

	return;
}

// Eventually we'll have it choose which type of export based on the arg here
void IDAP_run(int arg)
{
	// This try/catch is kinda worthless
	try
	{
		// Meat-o-licious
		bakmei_export();
	}
	catch (char *whatever)
	{
		//nothin
		msg("oh no!\n");
		msg("[!] %s\nAborting!\n", whatever);
	}

	for each(pair<ea_t, int*> ial in instruction_address_lookup)
	{
		if (ial.second != NULL)
			free((void *)ial.second);
	}		

	instruction_address_lookup.clear();
	global_branches.clear();
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
#pragma endregion

void bakmei_export(void)
{
	time_t start_time, run_time;
	int module_id = 0;
	char input_file[400]; // Seriously, why 400? I'm a lazy f
	void *db_info = NULL;
	int export_options = 0;

	get_input_file_path(input_file, 400);
	export_options = select_options(input_file, &db_info);

	if (export_options == -1)
	{
		msg("Aborting export.\n");
		return;
	}

	msg("Analyzing IDB...\n");
	
	// Get Start Time
	time(&start_time);

	// Create Module
	
	module_id = create_module(input_file);

	//DEBUG
	msg("[+] Created module\n");

	// Generate Cross References
	generate_cross_references();

	msg("[+] Created XREFs\n");
	// Set up Detailed Operands

	// Export Database
	export_database(export_options & 0xFF00, db_info);

	time(&run_time);
	msg("Done. Completed in %.2lf seconds.\n", difftime(run_time, start_time));
}

void generate_cross_references()
{
	vector<refpair_struct> *function_added = new vector<refpair_struct>();
	vector<refpair_struct> *basic_block_added = new vector<refpair_struct>();
	vector<refpair_struct>::iterator pair_iter;
	
	int *id_tuple_source, *id_tuple_dest;
	char *errmsg;
	char *sql;
	int result = 0;
	
	int sql_size = 82 /*INSN_TO_INSN length*/ + MAX_INT_STRLEN * 2 + 1 /*Z*/;

	struct refpair_struct refpair;
	
	for each(pair<refpair_struct, int> xref in global_branches)
	{
		try
		{
			id_tuple_source = instruction_address_lookup[xref.first.source];
            id_tuple_dest   = instruction_address_lookup[xref.first.dest];
 
			if (id_tuple_source == 0)
			{
				msg("[!] possible DREF at 0x%08x\n", xref.first.source);
				continue;
			}

			if (id_tuple_dest == 0)
			{
				msg("[!] possible DREF at 0x%08x\n", xref.first.dest);
				continue;
			}

			// 82 is the same length for the next two queries, so there's no need to reallocate
			sql = (char *) malloc(sql_size);           
			sprintf_s(sql, sql_size, INSERT_INSN_TO_INSN_XREFS, id_tuple_source[0], id_tuple_dest[0]);
	
			// Execute the sql statement
			result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);

			if (errmsg != NULL)
			{
				msg("Error %s", errmsg);
				sqlite3_free(errmsg);
				return;
			}

			refpair.source = id_tuple_source[1];
			refpair.dest = id_tuple_dest[1];
		
			pair_iter = find(basic_block_added->begin(), basic_block_added->end(), refpair);

            if (pair_iter == basic_block_added->end()) // Not found				
			{
				sprintf_s(sql, sql_size, INSERT_BLOC_TO_BLOC_XREFS, id_tuple_source[1], id_tuple_dest[1]);
				// Execute the sql statement
				result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
			 
				if (errmsg != NULL)
				{
					msg("Error %s", errmsg);
					sqlite3_free(errmsg);
					return;
				}
				basic_block_added->push_back(refpair);

				refpair.source = id_tuple_source[2];
				refpair.dest = id_tuple_dest[2];

				pair_iter = find(function_added->begin(), function_added->end(), refpair);

                if (refpair.source != refpair.dest && pair_iter == function_added->end())
				{
					sprintf_s(sql, sql_size, INSERT_FUNC_TO_FUNC_XREFS, id_tuple_source[2], id_tuple_dest[2]);

                    // Execute the sql statement
					result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);

					if (errmsg != NULL)
					{
						msg("Error %s", errmsg);
						sqlite3_free(errmsg);
						return;
					}
					function_added->push_back(refpair);
				}
			}
		}
		catch (char *str)// TODO: catch this properly! KeyError, details
		{			
            // TODO pick up all this lost code (Mainly thunks and unfunctioned code)
            msg("Missing instruction for 0x%08x / 0x%08x - It's probably not in a defined function. Skipping.", xref.first, xref.second);
		}

		// Deallocate always
		if (NULL != sql)
		{
			free(sql);
		}
		
	}

 //   // Build Data XRefs
	//delete(function_added); delete(basic_block_added);
 //   function_added = new vector<refpair_struct>();
	//basic_block_added = new vector<refpair_struct>();

 //   for (dref in global_drefs.keys())
	//{
 //       try
	//	{
 //           id_tuple_source = instruction_address_lookup[dref[0]]

 //           curs.execute(INSERT_INSN_TO_DATA_XREFS % (id_tuple_source[0], dref[1]))

 //           if not basic_block_added.has_key((id_tuple_source[1], dref[1]))
	//		{
 //               curs.execute(INSERT_BLOC_TO_DATA_XREFS % (id_tuple_source[1], dref[1]))
 //               basic_block_added[(id_tuple_source[1], dref[1])] = 1

 //               if id_tuple_source[2] != id_tuple_dest[2] and not function_added.has_key((id_tuple_source[2], dref[1]))
	//			{
 //                   curs.execute(INSERT_FUNC_TO_DATA_XREFS % (id_tuple_source[2], dref[1]))
 //                   function_added[(id_tuple_source[2], id_tuple_dest[2])] = 1
	//			}
	//		}
	//	}
 //       catch KeyError, details:
	//	{
 //           // TODO pick up all this lost code (Mainly thunks and unfunctioned code)
 //           msg("0x%08x: Missing instruction for Data Ref.", dref[0])
	//	}
	//}
}


void export_database(int database_type, void *dbinfo)
{
	if (database_type == DBTYPE_SQLITE)
	{
		export_sqlite_database((char *) dbinfo);
	}
	else if (database_type == DBTYPE_MYSQL)
	{
		export_mysql_database((mysql_data *) dbinfo);
	}
}

void export_mysql_database(mysql_data *mydbinfo)
{
	// TODO : for now we're going to pretend one module is ever inserted
	// into the database. I know that's a lie. You know that's a lie.
	// As the only two people to ever read through this code, let's keep
	// this a secret. We can make it our little game. 
	msg("Dumping MySQL\n");

	sqlite3_exec(db_ptr, "select * from module", &schema_dump_callback, NULL, NULL);


	/*MYSQL *mysqldb = NULL;

	mysql_init(mysqldb);

	mysql_real_connect(mysqldb, mydbinfo->hostname, mydbinfo->username; mydbinfo->password, "bakmei", 0, NULL, 0);

	mysql_query(mysqldb, sql);*/
}

void export_sqlite_database(char *outfile)
{	
	// If file exists, delete it
	// TODO
	
	char *extern_statement;
	int extern_size = strlen(outfile) + 29 /*SQL*/ + 1 /*Z*/;
	extern_statement = (char *) malloc(extern_size);

	sprintf_s(extern_statement, extern_size, "ATTACH DATABASE '%s' AS extern;", outfile);
	msg("%s\n", extern_statement);
	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, extern_statement, NULL, NULL, &errmsg);
	free(extern_statement);
	
	if (errmsg != NULL)
	{
		msg("[export 1] Error %s\n", errmsg);
		sqlite3_free(errmsg);
		return;
	}

	msg("Attached external database\n");

	for (int table_count = 0; table_count < TABLE_COUNT; table_count++)
	{
		char *src_table = SQLITE_CREATE_BAKMEI_SCHEMA[table_count];
		char *dst_table = (char *) malloc(strlen(src_table) + 7 /*extern.*/ + 1 /*Z*/);

		// Replace "TABLE " with "TABLE extern."
		memcpy(dst_table, src_table, 13);
		dst_table[13] = 'e'; dst_table[14] = 'x'; dst_table[15] = 't';
		dst_table[16] = 'e'; dst_table[17] = 'r'; dst_table[18] = 'n';
		dst_table[19] = '.';
		strcpy_s(dst_table + 20, strlen(src_table) + 8 - 20, src_table + 13);

        // Execute the sql statement
		result = sqlite3_exec(db_ptr, dst_table, NULL, NULL, &errmsg);	
		
		if (errmsg != NULL)
		{
			msg("[export 2] Error %s\n", errmsg);
			sqlite3_free(errmsg);
			return;
		}

		// 20 is the offset to the table name
		char *space = strchr(dst_table + 20, ' ');
		space[0] = '\0';

		int sql_size = (strlen(dst_table + 20) * 2) + 35/*sql*/ + 1/*Z*/;
		char *sql = (char *) malloc(sql_size);

		sprintf_s(sql, sql_size, "INSERT INTO extern.%s SELECT * FROM %s;", dst_table+20, dst_table+20);
        // Execute the sql statement
		result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);	

		if (errmsg != NULL)
		{
			msg("[export 2] Error %s\n", errmsg);
			sqlite3_free(errmsg);
			return;
		}
		free(sql);

		// Clean up
		free(dst_table); 
	}
	
	msg("closing the database [%s]\n", outfile);
	// actually close the database
	sqlite3_close(db_ptr);
	free(outfile);

	return;
}

// Returns 0 for standard, 1 for Advanced Operand Export
int select_options(char *input_filename, void **db_info)
{
	const char initial_format[] = 
		"STARTITEM 0\n"
		"HELP\n"
		"Database Types:\n\n"		
		"SQLite: This will export the database to a SQLite file stored locally on the \n"
		"hard disk. This is generally the faster option but limits the processing \n"
		"capabilities later on.\n\n"
		"MySQL:  This will export the information to a MySQL database either on \n"
		"your network or to 'localhost'. MySQL is more powerful for processing on \n"
		"later, but this process takes far longer due to network latency.\n\n"

		"Advanced Operand Export:\n\n"		
		"This exports not only the text representation of the instructions, but also \n"
		"the operand tree representations. It is not very stable at the present time, \n"
		"but will allow for advanced analysis when it is complete. Checking this box \n"
		"is NOT recommended as it will take a substantially longer time to export \n"
		"with no real value.\n"
		"ENDHELP\n"

		"Choose the database engine for export.\n"					// Title
		
		//  Radio Buttons
		"<#This will set the export engine to use SQLite.#"         // hint radio_sqlite
		"SQLite:R>\n"												// text radio_sqlite

		"<#This will set the export engine to use MySQL.#"          // hint radio_mysql
		"MySQL:R>>\n\n"												// text radio_mysql                     

		// Operand Tree Export (UNSTABLE)
		"<#This will export the full operand tree information. It it not stable.#"
		"Advanced Operand Export (UNSTABLE):C>>\n\n"
		;

	// TODO fill out HELP
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

	short advanced_export = 0;
	short db_format = 0;
	
	int ok = AskUsingForm_c(initial_format, &db_format, &advanced_export);
	if (!ok)
	{
		return -1;
	}

	// TODO : Handle Cancels

	// Don't want this zero based, it's a flag
	db_format = (db_format + 1) << 8;

	switch(db_format)
	{
		case DBTYPE_SQLITE:
			// SQLite			
			ok = create_sqlite_storage(input_filename, (char **) db_info);

			if (!ok)
				return -1;
	
			break;
		case DBTYPE_MYSQL:
			// MySQL
			*db_info = (struct mysql_data*) malloc(sizeof(struct mysql_data));
			
			strcpy_s(((mysql_data *)*db_info)->hostname, 255, "hostname");
			strcpy_s(((mysql_data *)*db_info)->username, 255, "username");
			strcpy_s(((mysql_data *)*db_info)->password, 255, "password");

			// TODO load vars
			ok = AskUsingForm_c(mysql_format, 
				&(((mysql_data*)*db_info)->hostname),
				&(((mysql_data*)*db_info)->username),
				&(((mysql_data*)*db_info)->password));
			if (!ok) 
				return -1;

			// TODO : test connection

			break;
	}

	// sqlite is used to aggregate the information regardless, this may need to 
	// change as we run into 64-bit addressing issues. Memory consumption may
	// play an issue too, this bridge will be crossed when we get to it.

	// Open in-memory SQL database
	sqlite3_open(":memory:", &db_ptr);
	
	// TODO This should be done on a file if we're not overwriting

	// Test for schema
	int table_count = 0;
	sqlite3_exec(db_ptr, "SELECT name FROM sqlite_master WHERE type='table';", &schema_check_callback, &table_count, NULL);

	if (table_count <= 0)
	{
		for (int i = 0; i < 16; i++)
		{
			sqlite3_exec(db_ptr, SQLITE_CREATE_BAKMEI_SCHEMA[i], NULL, NULL, NULL);
		}
	}
	else
	{
		if (table_count != 16)
		{
			msg("We might have problems, there were %d tables in the database\n", table_count);
		}
	}

	return (advanced_export & 0xFF) | (db_format);
}

int schema_dump_callback(void *results, int num_fields, char **fields, char **col_names)
{
	msg("fields: %d\n", num_fields);

	char *nullstring = "NULL";

	switch (num_fields)
	{
	case 7:
		// module
		char *modsql = "INSERT INTO module VALUES (%s, %s, %s, %s, %s, %s, %s);";

		char *id			= fields[0];
		char *name			= (fields[1] != NULL) ? sql_escape(fields[1]) : nullstring;
		char *base			= (fields[2] != NULL) ? fields[2] : nullstring;
		msg(fields[3]);msg("\n");
		char *signature		= (fields[3] != NULL) ? sql_escape(fields[3]) : nullstring;
		char *version		= (fields[4] != NULL) ? sql_escape(fields[4]) : nullstring;
		char *entry_point	= (fields[5] != NULL) ? fields[5] : nullstring;
		char *comment		= (fields[6] != NULL) ? fields[6] : nullstring;

		int sqlen = strlen(id) + strlen(name) + strlen(base) + strlen(signature) +
					strlen(version) + strlen(entry_point) + strlen(comment) + 41 /*Syntax*/ + 1/*Z*/;

		char *sql = (char *) malloc(sqlen);

		sprintf_s(sql, sqlen, modsql, id, name, base, signature, version, entry_point, comment);

		msg(sql);

		// Clean up
		if (name[0]		 != 'N') free(name);
		if (signature[0] != 'N') free(signature);
		if (version[0]	 != 'N') free(version);

		break;
	}

	msg("\n");

	return 0;
}

int schema_check_callback(void *counter, int num_fields, char **fields, char **col_names)
{
	// We only need to know *if* this function is hit, not really the contents
	*(int *)counter += 1;

	return 0;
}

int create_sqlite_storage(char *input_filename, char **output_filename)
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

		*output_filename = (char *) malloc(strlen(filename) + 1);
		strcpy_s(*output_filename, strlen(filename) + 1, filename);

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
				if (0 != remove(filename))
				{
					msg("Error code: %d deleting file.\n");
					throw "error deleting file";
				}
			}
		}
	}
	else
		return 0;

	return 1;
}

int create_module(char *input_file)
/*
	It is expected that the input file as passed in includes all path separators.
	At the moment, I will only parse by '\' as portability isn't my biggest concern.
*/
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
	free(sql);
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
			msg("%0.00f%% Completed...", last_pct * 100);
		}		
	}
	msg("\n");

    enumerate_imports(module_id);

	enumerate_rpc(module_id);

	return module_id;
}

char *sql_escape(char *source)
{
	int quote_counter = -1;
	char *temp = source-1;

	// Catch non-NULL empty strings
	if (strlen(source) == 0)
	{
		char *empty = (char *)malloc(3);
		empty[0] = '\''; empty[1] = '\''; empty[2] = 0;

		return empty;
	}

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


void generate_basic_block_branches(ea_t ea)
{
	// Branches to
	ea_t prev_code_ea = prev_not_tail(ea);
	ea_t prev_ea = prev_code_ea;
	struct refpair_struct refpair;

	while (!isCode(getFlags(prev_code_ea)))
	{
		prev_code_ea  = prev_not_tail(prev_code_ea);
	}

	ea_t xref = 0;
	xrefblk_t xb;

	for (bool ok=xb.first_to(ea, XREF_ALL); ok; ok=xb.next_to())
	{
		xref = xb.from;
		if (xref != prev_ea && xref != prev_code_ea && isCode(getFlags(xref)))
		{
			refpair.source = xref;
			refpair.dest = ea;
			global_branches[refpair] = 1;
		}
	}

	// Branches from
	for (bool ok=xb.first_from(ea, XREF_ALL); ok; ok=xb.next_from())
	{
		xref = xb.to;
		if (xref != next_not_tail(ea) && isCode(getFlags(xref)))
		{
			refpair.source = ea;
			refpair.dest = xref;
			global_branches[refpair] = 1;
		}
	}
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
	free(sql);
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

				// Add to Global branch table
				generate_basic_block_branches(addr);

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
	free(sql);
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

	// Allocate 2 chars per byte, plus null terminator
	char *byte_string = (char *)malloc((end_address - address)*2 + 2 /* SQL quotes */ + 1/*Z*/);

	byte_string[0] = '\'';

	int counter = 0;
	for (counter = 0; (address + counter) < end_address; counter++)
	{
		bytes[counter] = get_byte(address+counter);
		// TODO: may be best to convert to the string form here.
		
		sprintf_s((byte_string+1) + (counter * 2), 4 /*size in bytes*/, "%02x", bytes[counter]);

		if (counter > 20)
		{
			msg("0x%08x: Check instruction here for long bytes\n", address);
		}
	}

	// Close off the string. The +1 is to keep in mind the original quote, as the counter on it's own 
	// should be 1 more character over.
	byte_string[(counter*2)+1] = '\'';
	byte_string[(counter*2)+2] = 0;

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
					+ 20 /* max bytes size ?? escape later*/
					+ 2  /* quotes for byte string */
					+ 1 /*Z*/;

	char *sql = (char *) malloc(sql_size);
		
	sprintf_s(sql, sql_size, INSERT_INSTRUCTION, address, basic_block_id, function_id, module_id, safe_mnem, byte_string);
	free(safe_mnem); // Done with this, clean it up.
	free(byte_string); // Clean up the byte string, as it's no longer needed

	// Execute the sql statement
	char *errmsg;
	int result = sqlite3_exec(db_ptr, sql, NULL, NULL, &errmsg);
	free(sql);
	instruction_id = sqlite3_last_insert_rowid(db_ptr);

	int * addr_ref = (int *) malloc(sizeof(int) * 3);
	addr_ref[0] = instruction_id;
	addr_ref[1] = basic_block_id;
	addr_ref[2] = function_id;
	instruction_address_lookup[address] = addr_ref;

	create_operands(instruction_id, address);

	return;
}

void create_operands(int instruction_id, ea_t address)
{
	ua_ana0(address);	

	for (int opnum = 0; cmd.Operands[opnum].type != o_void; opnum++)
	{
		// If it's invisible, it's implicit and we don't care for our purposes
		// In theory, pyemu may need this information in the future.
		if (cmd.Operands[opnum].showed())	
			create_operand(instruction_id, address, opnum);		
	}

	return;
}


void create_operand(int instruction_id, ea_t address, int opnum, bool advanced)
{
	char op[256];
	int operand_id = 0;

	// Set op to string representation of operand
	ua_outop(address, op, 256, opnum);
	tag_remove(op, op, 256); // this will have to be done more intelligently to allow a max_size 256

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
	free(sql);
	operand_id = sqlite3_last_insert_rowid(db_ptr);
  	
	// We can safely leave now for old paimei usage
	if (!advanced)
		return;
  
	struct operand_leaf *root = new operand_leaf();
	vector<operand_leaf> tree;

	op_t ida_op = cmd.Operands[opnum];
  	
  	int index = 0;
  	
	root->operator_type = OPERATOR;
	root->immediate = 0;
	root->parent = -1;
	root->position = 0;

	switch(ida_op.dtyp)
	{
	case dt_byte:
		strcpy_s(root->symbol, 256, "b1");
		break;
	case dt_word:
		strcpy_s(root->symbol, 256, "b2");
		break;
	case dt_dword:
	case dt_float:
		strcpy_s(root->symbol, 256, "b4");
		break;
	case dt_double:
	case dt_qword:
		strcpy_s(root->symbol, 256, "b8");
		break;
	case dt_tbyte:
		strcpy_s(root->symbol, 256, "b_var");
		break;
	case dt_packreal:
		strcpy_s(root->symbol, 256, "b12");
		break;
	case dt_byte16:
		strcpy_s(root->symbol, 256, "b16");
		break;
	case dt_fword:
		strcpy_s(root->symbol, 256, "b6");
		break;
	case dt_3byte:
		strcpy_s(root->symbol, 256, "b3");
		break;
	default:
		// TODO Throw exception raise NotImplementedError, "Missing operand width for %s" % op_width[0]
		throw -1;
		break;
	}
 
	tree.assign(1, *root);
  	delete(root); // TODO see if corruption occurs
	struct operand_leaf *node = new operand_leaf();
	int size = 0;

	switch (ida_op.type)
	{
	case o_reg:		
        // General Register		
		node->operator_type = SYMBOL;
		strcpy_s(node->symbol, 256, op);
		node->immediate = 0;
		node->position = 1;
		node->parent = 0;

		tree.push_back(*node);
		delete(node);
		break;
    case o_mem:
        // Memory Reference
		create_memory_reference_operand(&tree, ida_op, op, address);
		break;
	case o_phrase:
        // Phrase (Base + Index)        
		create_phrase_operand(&tree, ida_op, op, address);
		break;
	case o_displ:
		// (+) Displacement
		create_displacement_operand(&tree, ida_op, op, address);
		break;
	case o_imm:
        // Immediate
        // TODO: String references aren't being saved.. Fix this
        // tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, GetOperandValue(address, position), 1, 0))
		node->operator_type = IMMEDIATE_INT;
		node->symbol[0] = '\0';
		node->immediate = ida_op.value;
		node->position = 1;
		node->parent = 0;

		tree.push_back(*node);
		delete(node);
		break;
	case o_far:
	case o_near:
		/*msg("Imm\n");*/
        // Immediate (Far, Near) Address
        // TODO: save substitution of ptr addresses
		node->operator_type = IMMEDIATE_INT;
		node->symbol[0] = NULL;
		node->immediate = ida_op.addr;
		node->position = 1;
		node->parent = 0;

		tree.push_back(*node);
		delete(node);        
		break;
	case o_idpspec3:
        // 386 Trace Register
		node->operator_type = SYMBOL;

		// "st(%d)" % ida_op.reg
		node->symbol[0] = 's';
		node->symbol[1] = 't';
		node->symbol[2] = '(';
		itoa(ida_op.reg, node->symbol+3, 10);
		size = strlen(node->symbol);
		node->symbol[size] = ')';
		node->symbol[size+1] = NULL;

		node->immediate = 0;
		node->parent = 0;
		node->position = 1;

		tree.push_back(*node);
		delete(node);        
		break;    
	case o_idpspec4:
        // MMX register
        node->operator_type = SYMBOL;

		// "mm%d" % ida_op.reg
		node->symbol[0] = 'm';
		node->symbol[1] = 'm';
		itoa(ida_op.reg, node->symbol+2, 10); //itoa will null terminate

		node->immediate = 0;
		node->parent = 0;
		node->position = 1;

		tree.push_back(*node);
		delete(node);        
		break;    
	case o_idpspec5:
        // XMM register
        node->operator_type = SYMBOL;

		// "xmm%d" % ida_op.reg
		node->symbol[0] = 'x';
		node->symbol[1] = 'm';
		node->symbol[2] = 'm';
		itoa(ida_op.reg, node->symbol+3, 10); //itoa will null terminate

		node->immediate = 0;
		node->parent = 0;
		node->position = 1;

		tree.push_back(*node);
		delete(node);        
		break;   
    default:
		delete(node);
        msg("0x%08x: Gonna die...\n", address);
        //raise NotImplementedError, "Currently can not process %d operands" % ida_op.type
		// TODO throw exception		
	}
	
	if  (tree.size() < 2)
	{
		msg("0x%08x: Gonna die...small tree. Optype: %d\n", address, ida_op.type);
        //raise NotImplementedError, "No operands for %d operands" % ida_op.type
		// TODO Throw exception
	}

    // TODO Insert into database
    // INSERT_EXPRESSION = "INSERT INTO expression (expr_type, symbol, immediate, position, parent_id) VALUES (%d, %s, %s, %d, %s)";

    //parent_lookup = {};
    //for entry in tree:
   
    //    tmp_symbol = "NULL"
    //    if entry[2]:
    //        tmp_symbol = ss.sql_safe_str(entry[2])
    //    tmp_immediate = "NULL"
    //    if entry[3]:
    //        tmp_immediate = entry[3]
    //    tmp_parent = "NULL"
    //    if entry[5]:
    //        tmp_parent = parent_lookup[entry[5]]
    //       
    //    sql = INSERT_EXPRESSION % (entry[1], tmp_symbol, tmp_immediate, entry[4], tmp_parent)
    //    curs.execute(sql)
    //    expr_id = curs.lastrowid
    //    parent_lookup[entry[0]] = expr_id
 
    //    // TODO : now might be a good time to eliminate dupes
  	
}

void create_displacement_operand(vector<operand_leaf> *tree, op_t ida_op, char *op, ea_t address)
{
	struct operand_leaf *node = new operand_leaf();
	int seg_off = 0;

	if (ida_op.specval>>16 != 0)
	{		
		node->operator_type = OPERATOR;
		strcpy_s(node->symbol, 256, ph.regNames[ida_op.specval>>16]); // This should give the segment prefix

		// Let's check
		msg("0x%08x: Segment: %s\n", address, node->symbol);

		node->immediate = 0;
		node->parent = 0;
		node->position = 1;

		seg_off = 1;
		tree->push_back(*node);

		delete(node); // clear and redefine
		node = new operand_leaf();
	}
	
	// DEBUG
	msg("Adding DEREF displacement\n");

	// Add deref operator
	node->operator_type = OPERATOR;
	node->symbol[0] = '['; node->symbol[1] = '\0';
	node->immediate = 0;
	node->parent = 0 + seg_off;
	node->position = 1 + seg_off;

	tree->push_back(*node);
	delete(node); node = new operand_leaf();

	// Check for a variable name
	// TODO : Now would be a good time to insert vars into the database
	/*
536 	    flags = GetFlags(ea)
537 	
538 	    var_name    = None
539 	    offset_adj  = 0
540 	
541 	    if (ord(ida_op.n) == 0 and isStkvar0(flags)) or (ord(ida_op.n) == 1 and isStkvar0(flags)):
542 	        var_name, offset_adj = get_stack_variable(ida_op, ea)
543 	
544 	    value = long(ida_op.addr)
545 	   
546 	    # convert to signed
547 	    if value > 2**31:
548				value = -(2**32 - value)
	*/
	// DEBUG
	msg("Adding SIB displacement\n");

	// Is there an SIB byte? (see intel.hpp:68)
    if (1 == ida_op.specflag1)
	{
		// DEBUG
		msg("0x%08x: Base Reg: %s\n", address, ph.regNames[ida_op.specflag2 & 0x7]);

		/*
552 	        base_reg = SIB_BASE_REGISTERS[ord(ida_op.specflag2)&0x7]
553 	
554 	        if base_reg == 'ebp' and temp.find('ebp') < 0:
555 	            base_reg = ''
556 	
557 	        scale = (None, 2, 4, 8)[ord(ida_op.specflag2)>>6]
558 	
559 	        if scale:
560 	            plus_off = 2+seg_off # seg_off can be changed by the following function
561 	            create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea)
562 	            tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 4+seg_off, 2+seg_off))
563 	        else:
564 	            index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]
565 	
566 	            if index_reg != "esp":
567 	                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
568 	                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
569 	                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, index_reg, None, 4+seg_off, 2+seg_off))
570 	                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 5+seg_off, 2+seg_off))
571 	                # TODO: save substitution
572 	            else:
573 	                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
574 	                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
575 	                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 4+seg_off, 2+seg_off))
576 	                # TODO: save substitution
	*/
	}
	else
	{
		/*
578 	       tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
579 	       reg = REGISTERS[getseg(ea).bitness+1][ida_op.reg]
580 	       tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, reg, None, 3+seg_off, 2+seg_off))
581 	       tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, value, 4+seg_off, 2+seg_off))
582 	       # TODO: save substitution (if any)
		*/
	}	
	return;
}

void create_phrase_operand(vector<operand_leaf> *tree, op_t ida_op, char *op, ea_t address)
{
	struct operand_leaf *node = new operand_leaf();
	int seg_off = 0;

	if (ida_op.specval>>16 != 0)
	{		
		node->operator_type = OPERATOR;
		strcpy_s(node->symbol, 256, ph.regNames[ida_op.specval>>16]); // This should give the segment prefix

		// Let's check
		msg("0x%08x: Segment: %s\n", address, node->symbol);

		node->immediate = 0;
		node->parent = 0;
		node->position = 1;

		seg_off = 1;
		tree->push_back(*node);

		delete(node); // clear and redefine
		node = new operand_leaf();
	}
	
	// DEBUG
	msg("Adding DEREF phrase\n");

	// Add deref operator
	node->operator_type = OPERATOR;
	node->symbol[0] = '['; node->symbol[1] = '\0';
	node->immediate = 0;
	node->parent = 0 + seg_off;
	node->position = 1 + seg_off;

	tree->push_back(*node);
	delete(node); node = new operand_leaf();

	// DEBUG
	msg("Adding SIB phrase\n");

	// Is there an SIB byte? (see intel.hpp:68)
    if (1 == ida_op.specflag1)
	{
		// DEBUG
		msg("0x%08x: Base Reg: %s\n", address, ph.regNames[ida_op.specflag2 & 0x7]);

		/*
        base_reg = SIB_BASE_REGISTERS[ord(ida_op.specflag2)&0x7]

        if base_reg == 'ebp' and temp.find('ebp') < 0:
            base_reg = ''

        scale = (None, 2, 4, 8)[ord(ida_op.specflag2)>>6]

        if scale:
			create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea)
            // Is there a value at the end?
        else:
            index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]

            if index_reg == "esp":
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
            else:
                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, index_reg, None, 4+seg_off, 2+seg_off))

                // TODO: save substitution
	*/
	}
    else
	{
     /*   reg = REGISTERS[getseg(ea).bitness+1][ida_op.phrase]
        tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, reg, None, 2+seg_off, 1+seg_off))*/
	}
	
	return;
}

// TODO Save the address name
void create_memory_reference_operand(vector<operand_leaf> *tree, op_t ida_op, char *op, ea_t address)
{
	struct operand_leaf *node = new operand_leaf();
	int seg_off = 0;

	if (ida_op.specval>>16 != 0)
	{		
		node->operator_type = OPERATOR;
		strcpy_s(node->symbol, 256, ph.regNames[ida_op.specval>>16]); // This should give the segment prefix

		// Let's check
		msg("0x%08x: Segment: %s\n", address, node->symbol);

		node->immediate = 0;
		node->parent = 0;
		node->position = 1;

		seg_off = 1;
		tree->push_back(*node);

		delete(node); // clear and redefine
		node = new operand_leaf();
	}

	// DEBUG
	msg("Adding DEREF memref\n");

	// Add deref operator
	node->operator_type = OPERATOR;
	node->symbol[0] = '['; node->symbol[1] = '\0';
	node->immediate = 0;
	node->parent = 0 + seg_off;
	node->position = 1 + seg_off;

	tree->push_back(*node);
	delete(node); node = new operand_leaf();
	
	// TODO finish after other errors are sorted.

	// DEBUG
	msg("Adding SIB memref\n");

    // Is there an SIB byte? (see intel.hpp:68)
    if (1 == ida_op.specflag1)
	{
		// DEBUG
		msg("0x%08x: Base Reg: %s\n", address, ph.regNames[ida_op.specflag2 & 0x7]);

		/*
        base_reg = SIB_BASE_REGISTERS[ida_op.specflag2 & 0x7]
 	
		if base_reg == 'ebp' and temp.find('ebp') < 0:
 	            base_reg = ''
 	
 	        scale = (None, 2, 4, 8)[ord(ida_op.specflag2)>>6]
 	
 	        if scale:
 	            plus_off = 2+seg_off # seg_off can be changed by the following function
 	            create_scaled_expression(tree, base_reg, scale, ida_op, seg_off, ea)
 	            tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
 	        else:
 	            index_reg = SIB_BASE_REGISTERS[(ord(ida_op.specflag2)>>3)&0x7]
 	
 	            if index_reg != "esp":
 	                print "0x%08x: Gonna die..." % ea
 	                raise NotImplementedError, "Don't know how to handle index registers"
 	            else:
 	                tree.append(create_expression_entry(NODE_TYPE_OPERATOR_ID, NODE_TYPE_OPERATOR_PLUS, None, 2+seg_off, 1+seg_off))
 	                tree.append(create_expression_entry(NODE_TYPE_SYMBOL_ID, base_reg, None, 3+seg_off, 2+seg_off))
 	                tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 4+seg_off, 2+seg_off))
 	                // TODO: save substitution
			*/
	}
 	else
	{
		//tree.append(create_expression_entry(NODE_TYPE_IMMEDIATE_INT_ID, None, ida_op.addr, 1+seg_off, 0+seg_off))
	}

	delete(node);

	return;
}


void enumerate_imports(int module_id)
{
	msg("Enumerating imports...\n");
}

void enumerate_rpc(int module_id)
{
	msg("Enumerating RPC functions...\n");
}