/*
 * pg_migrate.c: bin/pg_migrate.c
 *
 * Portions Copyright (c) 2008-2011, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
 * Portions Copyright (c) 2011, Itagaki Takahiro
 * Portions Copyright (c) 2012-2020, The Reorg Development Team
 */

/**
 * @brief Client Modules
 */

const char *PROGRAM_URL		= "https://github.com/phillbaker/pg_migrate";
const char *PROGRAM_ISSUES	= "https://github.com/phillbaker/pg_migrate/issues";

#ifdef MIGRATE_VERSION
/* macro trick to stringify a macro expansion */
#define xstr(s) str(s)
#define str(s) #s
const char *PROGRAM_VERSION = xstr(MIGRATE_VERSION);
#else
const char *PROGRAM_VERSION = "unknown";
#endif

#include "pgut/pgut-fe.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>


#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif


#ifndef HIGHBIT
#define HIGHBIT					(0x80)
#define IS_HIGHBIT_SET(ch)		((unsigned char)(ch) & HIGHBIT)
#endif

#ifndef IsToken
#define IsToken(c) \
	(IS_HIGHBIT_SET((c)) || isalnum((unsigned char) (c)) || (c) == '_')
#endif

/*
 * APPLY_COUNT: Number of applied logs per transaction. Larger values
 * could be faster, but will be long transactions in the REDO phase.
 */
#define APPLY_COUNT		1000

/* Once we get down to seeing fewer than this many tuples in the
 * log table, we'll say that we're ready to perform the switch.
 */
#define MIN_TUPLES_BEFORE_SWITCH	20

/* poll() or select() timeout, in seconds */
#define POLL_TIMEOUT    3

/* Compile an array of existing transactions which are active during
 * pg_migrate's setup. Some transactions we can safely ignore:
 *  a. The '1/1, -1/0' lock skipped is from the bgwriter on newly promoted
 *     servers. See https://github.com/reorg/pg_reorg/issues/1
 *  b. Our own database connections
 *  c. Other pg_migrate clients, as distinguished by application_name, which
 *     may be operating on other tables at the same time. See
 *     https://github.com/reorg/pg_repack/issues/1
 *  d. open transactions/locks existing on other databases than the actual
 *     processing relation (except for locks on shared objects)
 *  e. VACUUMs which are always executed outside transaction blocks.
 *
 * Note, there is some redundancy in how the filtering is done (e.g. excluding
 * based on pg_backend_pid() and application_name), but that shouldn't hurt
 * anything. Also, the test of application_name is not bulletproof -- for
 * instance, the application name when running installcheck will be
 * pg_regress.
 */
#define SQL_XID_SNAPSHOT_90200 \
	"SELECT coalesce(array_agg(l.virtualtransaction), '{}') " \
	"  FROM pg_locks AS l " \
	"  LEFT JOIN pg_stat_activity AS a " \
	"    ON l.pid = a.pid " \
	"  LEFT JOIN pg_database AS d " \
	"    ON a.datid = d.oid " \
	"  WHERE l.locktype = 'virtualxid' " \
	"  AND l.pid NOT IN (pg_backend_pid(), $1) " \
	"  AND (l.virtualxid, l.virtualtransaction) <> ('1/1', '-1/0') " \
	"  AND (a.application_name IS NULL OR a.application_name <> $2)" \
	"  AND a.query !~* E'^\\\\s*vacuum\\\\s+' " \
	"  AND a.query !~ E'^autovacuum: ' " \
	"  AND ((d.datname IS NULL OR d.datname = current_database()) OR l.database = 0)"

#define SQL_XID_SNAPSHOT_90000 \
	"SELECT coalesce(array_agg(l.virtualtransaction), '{}') " \
	"  FROM pg_locks AS l " \
	"  LEFT JOIN pg_stat_activity AS a " \
	"    ON l.pid = a.procpid " \
	"  LEFT JOIN pg_database AS d " \
	"    ON a.datid = d.oid " \
	"  WHERE l.locktype = 'virtualxid' " \
	"  AND l.pid NOT IN (pg_backend_pid(), $1) " \
	"  AND (l.virtualxid, l.virtualtransaction) <> ('1/1', '-1/0') " \
	"  AND (a.application_name IS NULL OR a.application_name <> $2)" \
	"  AND a.current_query !~* E'^\\\\s*vacuum\\\\s+' " \
	"  AND a.current_query !~ E'^autovacuum: ' " \
	"  AND ((d.datname IS NULL OR d.datname = current_database()) OR l.database = 0)"

/* application_name is not available before 9.0. The last clause of
 * the WHERE clause is just to eat the $2 parameter (application name).
 */
#define SQL_XID_SNAPSHOT_80300 \
	"SELECT coalesce(array_agg(l.virtualtransaction), '{}') " \
	"  FROM pg_locks AS l" \
	"  LEFT JOIN pg_stat_activity AS a " \
	"    ON l.pid = a.procpid " \
	"  LEFT JOIN pg_database AS d " \
	"    ON a.datid = d.oid " \
	" WHERE l.locktype = 'virtualxid' AND l.pid NOT IN (pg_backend_pid(), $1)" \
	" AND (l.virtualxid, l.virtualtransaction) <> ('1/1', '-1/0') " \
	" AND a.current_query !~* E'^\\\\s*vacuum\\\\s+' " \
	" AND a.current_query !~ E'^autovacuum: ' " \
	" AND ((d.datname IS NULL OR d.datname = current_database()) OR l.database = 0)" \
	" AND ($2::text IS NOT NULL)"

#define SQL_XID_SNAPSHOT \
	(PQserverVersion(connection) >= 90200 ? SQL_XID_SNAPSHOT_90200 : \
	 (PQserverVersion(connection) >= 90000 ? SQL_XID_SNAPSHOT_90000 : \
	  SQL_XID_SNAPSHOT_80300))


/* Later, check whether any of the transactions we saw before are still
 * alive, and wait for them to go away.
 */
#define SQL_XID_ALIVE \
	"SELECT pid FROM pg_locks WHERE locktype = 'virtualxid'"\
	" AND pid <> pg_backend_pid() AND virtualtransaction = ANY($1)"

/* To be run while our main connection holds an AccessExclusive lock on the
 * target table, and our secondary conn is attempting to grab an AccessShare
 * lock. We know that "granted" must be false for these queries because
 * we already hold the AccessExclusive lock. Also, we only care about other
 * transactions trying to grab an ACCESS EXCLUSIVE lock, because we are only
 * trying to kill off disallowed DDL commands, e.g. ALTER TABLE or TRUNCATE.
 */
#define CANCEL_COMPETING_LOCKS \
	"SELECT pg_cancel_backend(pid) FROM pg_locks WHERE locktype = 'relation'"\
	" AND granted = false AND relation = %u"\
	" AND mode = 'AccessExclusiveLock' AND pid <> pg_backend_pid()"

#define KILL_COMPETING_LOCKS \
	"SELECT pg_terminate_backend(pid) "\
	"FROM pg_locks WHERE locktype = 'relation'"\
	" AND granted = false AND relation = %u"\
	" AND mode = 'AccessExclusiveLock' AND pid <> pg_backend_pid()"

#define COUNT_COMPETING_LOCKS \
	"SELECT pid FROM pg_locks WHERE locktype = 'relation'" \
	" AND granted = false AND relation = %u" \
	" AND mode = 'AccessExclusiveLock' AND pid <> pg_backend_pid()"

/* Will be used as a unique prefix for advisory locks. */
#define MIGRATE_LOCK_PREFIX_STR "16185446"

typedef enum
{
	UNPROCESSED,
	INPROGRESS,
	FINISHED
} index_status_t;

/*
 * per-index information
 */
typedef struct migrate_index
{
	Oid				target_oid;		/* target: OID */
	const char	   *create_index;	/* CREATE INDEX */
	index_status_t  status; 		/* Track parallel build statuses. */
	int             worker_idx;		/* which worker conn is handling */
} migrate_index;

/*
 * per-table information
 */
typedef struct migrate_table
{
	const char	   *target_name;	/* target: relname */
	Oid				target_oid;		/* target: OID */
	Oid				target_toast;	/* target: toast OID */
	Oid				target_tidx;	/* target: toast index OID */
	Oid				pkid;			/* target: PK OID */
	Oid				ckid;			/* target: CK OID */
	const char	   *create_pktype;	/* CREATE TYPE pk */
	const char	   *create_log;		/* CREATE TABLE log */
	const char	   *create_trigger;	/* CREATE TRIGGER migrate_trigger */
	const char	   *enable_trigger;	/* ALTER TABLE ENABLE ALWAYS TRIGGER migrate_trigger */
	const char	   *create_table;	/* CREATE TABLE table AS SELECT WITH NO DATA*/
	const char	   *copy_data;		/* INSERT INTO */
	const char	   *alter_col_storage;	/* ALTER TABLE ALTER COLUMN SET STORAGE */
	const char	   *drop_columns;	/* ALTER TABLE DROP COLUMNs */
	const char	   *delete_log;		/* DELETE FROM log */
	const char	   *lock_table;		/* LOCK TABLE table */
	const char	   *sql_peek;		/* SQL used in flush */
	const char	   *sql_insert;		/* SQL used in flush */
	const char	   *sql_delete;		/* SQL used in flush */
	const char	   *sql_update;		/* SQL used in flush */
	const char	   *sql_pop;		/* SQL used in flush */
	int             n_indexes;      /* number of indexes */
	migrate_index   *indexes;        /* info on each index */
} migrate_table;

/*
 * per-table information
 */
typedef struct migrate_foreign_key
{
	const char *table_schema;
	const char *constraint_name;
	const char *table_name;
	const char *column_name;
	const char *foreign_table_schema;
	const char *foreign_table_name;
	const char *foreign_column_name;
} migrate_foreign_key;

typedef struct IndexDef
{
	char *create;	/* CREATE INDEX or CREATE UNIQUE INDEX */
	char *index;	/* index name including schema */
	char *table;	/* table name including schema */
	char *type;		/* btree, hash, gist or gin */
	char *columns;	/* column definition */
	char *options;	/* options after columns, before TABLESPACE (e.g. COLLATE) */
	char *tablespace; /* tablespace if specified */
	char *where;	/* WHERE content if specified */
} IndexDef;

static char *skip_const(const char *original_sql, char *sql, const char *arg1, const char *arg2);
static char *skip_ident(const char *original_sql, char *sql);
static char *parse_error(const char *original_sql);
static char *skip_until_const(const char *original_sql, char *sql, const char *what);
static char *skip_until(const char *original_sql, char *sql, char end);

static bool is_superuser(void);
static void check_tablespace(void);
static bool preliminary_checks(char *errbuf, size_t errsize);
static bool is_requested_relation_exists(char *errbuf, size_t errsize);
static void repack_all_databases(const char *order_by);
static bool repack_one_database(const char *order_by, char *errbuf, size_t errsize);
static void migrate_one_table(migrate_table *table, const char *order_by, char *errbuf, size_t errsize);
static bool repack_table_indexes(PGresult *index_details);
static bool repack_all_indexes(char *errbuf, size_t errsize);
static void migrate_cleanup(bool fatal, const migrate_table *table);
static void migrate_cleanup_callback(bool fatal, void *userdata);
static bool rebuild_indexes(const migrate_table *table);

static char *getstr(PGresult *res, int row, int col);
static Oid getoid(PGresult *res, int row, int col);
static bool advisory_lock(PGconn *conn, const char *relid);
static bool lock_exclusive(PGconn *conn, const char *relid, const char *lock_query, bool start_xact);
static bool kill_ddl(PGconn *conn, Oid relid, bool terminate);
static bool lock_access_share(PGconn *conn, Oid relid, const char *target_name);
static bool apply_alter_statement(PGconn *conn, Oid relid, const char *alter_sql);
static int strpos(char *hay, char *needle);
static void parse_indexdef(IndexDef *stmt, char *sql, const char *idxname, const char *tblname);

#define SQLSTATE_INVALID_SCHEMA_NAME	"3F000"
#define SQLSTATE_UNDEFINED_FUNCTION		"42883"
#define SQLSTATE_QUERY_CANCELED			"57014"

static bool sqlstate_equals(PGresult *res, const char *state)
{
	return strcmp(PQresultErrorField(res, PG_DIAG_SQLSTATE), state) == 0;
}

static bool				analyze = true;
static bool				alldb = false;
static bool				noorder = false;
static SimpleStringList	parent_table_list = {NULL, NULL};
static SimpleStringList	alter_list = {NULL, NULL};
static SimpleStringList	table_list = {NULL, NULL};
static SimpleStringList	schema_list = {NULL, NULL};
static char				*orderby = NULL;
static char				*tablespace = NULL;
static bool				moveidx = false;
static SimpleStringList	r_index = {NULL, NULL};
static bool				only_indexes = false;
static int				wait_timeout = 60;	/* in seconds */
static int				jobs = 0;	/* number of concurrent worker conns. */
static bool				execute_allowed = false;
static unsigned int		temp_obj_num = 0; /* temporary objects counter */
static bool				no_kill_backend = false; /* abandon when timed-out */
static bool				no_superuser_check = false;
static SimpleStringList	exclude_extension_list = {NULL, NULL}; /* don't migrate tables of these extensions */

/* buffer should have at least 11 bytes */
static char *
utoa(unsigned int value, char *buffer)
{
	sprintf(buffer, "%u", value);

	return buffer;
}

static pgut_option options[] =
{
	{ 'l', 't', "table", &table_list },
	{ 'l', 'a', "alter", &alter_list },
	{ 'l', 's', "schema", &schema_list },
	{ 'b', 'N', "execute", &execute_allowed },
	{ 'i', 'T', "wait-timeout", &wait_timeout },
	{ 'i', 'j', "jobs", &jobs },
	{ 'b', 'D', "no-kill-backend", &no_kill_backend },
	{ 'b', 'k', "no-superuser-check", &no_superuser_check },
	{ 0 },
};

int
main(int argc, char *argv[])
{
	int						i;
	char						errbuf[256];

	i = pgut_getopt(argc, argv, options);

	if (i == argc - 1)
		dbname = argv[i];
	else if (i < argc)
		ereport(ERROR,
			(errcode(EINVAL),
			 errmsg("too many arguments")));

	check_tablespace();

	if (!alter_list.head)
		elog(INFO, "No alter statements, not executing migration");

	if (!execute_allowed)
		elog(INFO, "Dry run enabled, not executing migration, run with --execute to process.");

	if (!repack_one_database(orderby, errbuf, sizeof(errbuf)))
		ereport(ERROR,
			(errcode(ERROR), errmsg("%s failed with error: %s", PROGRAM_NAME, errbuf)));

	return 0;
}


/*
 * Test if the current user is a database superuser.
 * Borrowed from psql/common.c
 *
 * Note: this will correctly detect superuserness only with a protocol-3.0
 * or newer backend; otherwise it will always say "false".
 */
bool
is_superuser(void)
{
	const char *val;

	if (no_superuser_check)
		return true;

	if (!connection)
		return false;

	val = PQparameterStatus(connection, "is_superuser");

	if (val && strcmp(val, "on") == 0)
		return true;

	return false;
}

/*
 * Check if the tablespace requested exists.
 *
 * Raise an exception on error.
 */
void
check_tablespace()
{
	PGresult		*res = NULL;
	const char *params[1];

	if (tablespace == NULL)
	{
		/* nothing to check, but let's see the options */
		if (moveidx)
		{
			ereport(ERROR,
				(errcode(EINVAL),
				 errmsg("cannot specify --moveidx (-S) without --tablespace (-s)")));
		}
		return;
	}

	/* check if the tablespace exists */
	reconnect(ERROR);
	params[0] = tablespace;
	res = execute_elevel(
		"select spcname from pg_tablespace where spcname = $1",
		1, params, DEBUG2);

	if (PQresultStatus(res) == PGRES_TUPLES_OK)
	{
		if (PQntuples(res) == 0)
		{
			ereport(ERROR,
				(errcode(EINVAL),
				 errmsg("the tablespace \"%s\" doesn't exist", tablespace)));
		}
	}
	else
	{
		ereport(ERROR,
			(errcode(EINVAL),
			 errmsg("error checking the namespace: %s",
				 PQerrorMessage(connection))));
	}

	CLEARPGRES(res);
}

/*
 * Perform sanity checks before beginning work. Make sure pg_migrate is
 * installed in the database, the user is a superuser, etc.
 */
static bool
preliminary_checks(char *errbuf, size_t errsize){
	bool			ret = false;
	PGresult		*res = NULL;

	if (!is_superuser()) {
		if (errbuf)
			snprintf(errbuf, errsize, "You must be a superuser to use %s",
					 PROGRAM_NAME);
		goto cleanup;
	}

	/* Query the extension version. Exit if no match */
	res = execute_elevel("select migrate.version(), migrate.version_sql()",
		0, NULL, DEBUG2);
	if (PQresultStatus(res) == PGRES_TUPLES_OK)
	{
		const char	   *libver;
		char			buf[64];

		/* the string is something like "pg_migrate 1.1.7" */
		snprintf(buf, sizeof(buf), "%s %s", PROGRAM_NAME, PROGRAM_VERSION);

		/* check the version of the C library */
		libver = getstr(res, 0, 0);
		if (0 != strcmp(buf, libver))
		{
			if (errbuf)
				snprintf(errbuf, errsize,
					"program '%s' does not match database library '%s'",
					buf, libver);
			goto cleanup;
		}

		/* check the version of the SQL extension */
		libver = getstr(res, 0, 1);
		if (0 != strcmp(buf, libver))
		{
			if (errbuf)
				snprintf(errbuf, errsize,
					"extension '%s' required, found extension '%s'",
					buf, libver);
			goto cleanup;
		}
	}
	else
	{
		if (sqlstate_equals(res, SQLSTATE_INVALID_SCHEMA_NAME)
			|| sqlstate_equals(res, SQLSTATE_UNDEFINED_FUNCTION))
		{
			/* Schema migrate does not exist, or version too old (version
			 * functions not found). Skip the database.
			 */
			if (errbuf)
				snprintf(errbuf, errsize,
					"%s %s is not installed in the database",
					PROGRAM_NAME, PROGRAM_VERSION);
		}
		else
		{
			/* Return the error message otherwise */
			if (errbuf)
				snprintf(errbuf, errsize, "%s", PQerrorMessage(connection));
		}
		goto cleanup;
	}
	CLEARPGRES(res);

	/* Disable statement timeout. */
	command("SET statement_timeout = 0", 0, NULL);

	/* Restrict search_path to system catalog. */
	command("SET search_path = pg_catalog, pg_temp, public", 0, NULL);

	/* To avoid annoying "create implicit ..." messages. */
	command("SET client_min_messages = warning", 0, NULL);

	ret = true;

cleanup:
	CLEARPGRES(res);
	return ret;
}

/*
 * Check the presence of tables specified by --parent-table and --table
 * otherwise format user-friendly message
 */
static bool
is_requested_relation_exists(char *errbuf, size_t errsize){
	bool			ret = false;
	PGresult		*res = NULL;
	const char	    **params = NULL;
	int				iparam = 0;
	StringInfoData	sql;
	int				num_relations;
	SimpleStringListCell   *cell;

	num_relations = simple_string_list_size(parent_table_list) +
					simple_string_list_size(table_list);

	/* nothing was implicitly requested, so nothing to do here */
	if (num_relations == 0)
		return true;

	/* has no suitable to_regclass(text) */
	if (PQserverVersion(connection)<90600)
		return true;

	params = pgut_malloc(num_relations * sizeof(char *));
	initStringInfo(&sql);
	appendStringInfoString(&sql, "SELECT r FROM (VALUES ");

	for (cell = table_list.head; cell; cell = cell->next)
	{
		appendStringInfo(&sql, "($%d)", iparam + 1);
		params[iparam++] = cell->val;
		if (iparam < num_relations)
			appendStringInfoChar(&sql, ',');
	}
	for (cell = parent_table_list.head; cell; cell = cell->next)
	{
		appendStringInfo(&sql, "($%d)", iparam + 1);
		params[iparam++] = cell->val;
		if (iparam < num_relations)
			appendStringInfoChar(&sql, ',');
	}
	appendStringInfoString(&sql,
		") AS given_t(r)"
		" WHERE NOT EXISTS("
		"  SELECT FROM migrate.tables WHERE relid=to_regclass(given_t.r) )"
	);

	/* double check the parameters array is sane */
	if (iparam != num_relations)
	{
		if (errbuf)
			snprintf(errbuf, errsize,
				"internal error: bad parameters count: %i instead of %i",
				 iparam, num_relations);
		goto cleanup;
	}

	res = execute_elevel(sql.data, iparam, params, DEBUG2);
	if (PQresultStatus(res) == PGRES_TUPLES_OK)
	{
		int 	num;

		num = PQntuples(res);

		if (num != 0)
		{
			int i;
			StringInfoData	rel_names;
			initStringInfo(&rel_names);

			for (i = 0; i < num; i++)
			{
				appendStringInfo(&rel_names, "\"%s\"", getstr(res, i, 0));
				if ((i + 1) != num)
					appendStringInfoString(&rel_names, ", ");
			}

			if (errbuf)
			{
				if (num > 1)
					snprintf(errbuf, errsize,
							"relations do not exist: %s", rel_names.data);
				else
					snprintf(errbuf, errsize,
							"ERROR:  relation %s does not exist", rel_names.data);
			}
			termStringInfo(&rel_names);
		}
		else
			ret = true;
	}
	else
	{
		if (errbuf)
			snprintf(errbuf, errsize, "%s", PQerrorMessage(connection));
	}
	CLEARPGRES(res);

cleanup:
	CLEARPGRES(res);
	termStringInfo(&sql);
	free(params);
	return ret;
}

/*
 * Call repack_one_database for each database.
 */
static void
repack_all_databases(const char *orderby)
{
	PGresult   *result;
	int			i;

	dbname = "postgres";
	reconnect(ERROR);

	if (!is_superuser())
		elog(ERROR, "You must be a superuser to use %s", PROGRAM_NAME);

	result = execute("SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;", 0, NULL);
	disconnect();

	for (i = 0; i < PQntuples(result); i++)
	{
		bool	ret;
		char	errbuf[256];

		dbname = PQgetvalue(result, i, 0);

		elog(INFO, "repacking database \"%s\"", dbname);
		if (execute_allowed)
		{
			ret = repack_one_database(orderby, errbuf, sizeof(errbuf));
			if (!ret)
				elog(INFO, "database \"%s\" skipped: %s", dbname, errbuf);
		}
	}

	CLEARPGRES(result);
}

/* result is not copied */
static char *
getstr(PGresult *res, int row, int col)
{
	if (PQgetisnull(res, row, col))
		return NULL;
	else
		return PQgetvalue(res, row, col);
}

static Oid
getoid(PGresult *res, int row, int col)
{
	if (PQgetisnull(res, row, col))
		return InvalidOid;
	else
		return (Oid)strtoul(PQgetvalue(res, row, col), NULL, 10);
}

/*
 * Call migrate_one_table for the target tables or each table in a database.
 */
static bool
repack_one_database(const char *orderby, char *errbuf, size_t errsize)
{
	bool					ret = false;
	PGresult			   *res = NULL;
	int						i;
	int						num;
	StringInfoData			sql;
	SimpleStringListCell   *cell;
	const char			  **params = NULL;
	int						iparam = 0;
	size_t					num_parent_tables,
							num_tables,
							num_schemas,
							num_params,
							num_excluded_extensions;

	num_parent_tables = simple_string_list_size(parent_table_list);
	num_tables = simple_string_list_size(table_list);
	num_schemas = simple_string_list_size(schema_list);
	num_excluded_extensions = simple_string_list_size(exclude_extension_list);

	/* 1st param is the user-specified tablespace */
	num_params = num_excluded_extensions +
				 num_parent_tables +
				 num_tables +
				 num_schemas + 1;
	params = pgut_malloc(num_params * sizeof(char *));

	initStringInfo(&sql);

	reconnect(ERROR);

	/* No sense in setting up concurrent workers if --jobs=1 */
	if (jobs > 1)
		setup_workers(jobs);

	if (!preliminary_checks(errbuf, errsize))
		goto cleanup;

	if (!is_requested_relation_exists(errbuf, errsize))
		goto cleanup;

	/* acquire target tables */
	appendStringInfoString(&sql,
		"SELECT t.*,"
		" coalesce(v.tablespace, t.tablespace_orig) as tablespace_dest"
		" FROM migrate.tables t, "
		" (VALUES (quote_ident($1::text))) as v (tablespace)"
		" WHERE ");

	params[iparam++] = tablespace;
	if (num_tables || num_parent_tables)
	{
		/* standalone tables */
		if (num_tables)
		{
			appendStringInfoString(&sql, "(");
			for (cell = table_list.head; cell; cell = cell->next)
			{
				/* Construct table name placeholders to be used by PQexecParams */
				appendStringInfo(&sql, "relid = $%d::regclass", iparam + 1);
				params[iparam++] = cell->val;
				if (cell->next)
					appendStringInfoString(&sql, " OR ");
			}
			appendStringInfoString(&sql, ")");
		}

		if (num_tables && num_parent_tables)
			appendStringInfoString(&sql, " OR ");

		/* parent tables + inherited children */
		if (num_parent_tables)
		{
			appendStringInfoString(&sql, "(");
			for (cell = parent_table_list.head; cell; cell = cell->next)
			{
				/* Construct table name placeholders to be used by PQexecParams */
				appendStringInfo(&sql,
								 "relid = ANY(migrate.get_table_and_inheritors($%d::regclass))",
								 iparam + 1);
				params[iparam++] = cell->val;
				if (cell->next)
					appendStringInfoString(&sql, " OR ");
			}
			appendStringInfoString(&sql, ")");
		}
	}
	else if (num_schemas)
	{
		appendStringInfoString(&sql, "schemaname IN (");
		for (cell = schema_list.head; cell; cell = cell->next)
		{
			/* Construct schema name placeholders to be used by PQexecParams */
			appendStringInfo(&sql, "$%d", iparam + 1);
			params[iparam++] = cell->val;
			if (cell->next)
				appendStringInfoString(&sql, ", ");
		}
		appendStringInfoString(&sql, ")");
	}
	else
	{
		appendStringInfoString(&sql, "pkid IS NOT NULL");
	}

	/* Exclude tables which belong to extensions */
	if (exclude_extension_list.head)
	{
		appendStringInfoString(&sql, " AND t.relid NOT IN"
									 "  (SELECT d.objid::regclass"
									 "   FROM pg_depend d JOIN pg_extension e"
									 "   ON d.refobjid = e.oid"
									 "   WHERE d.classid = 'pg_class'::regclass AND (");

		/* List all excluded extensions */
		for (cell = exclude_extension_list.head; cell; cell = cell->next)
		{
			appendStringInfo(&sql, "e.extname = $%d", iparam + 1);
			params[iparam++] = cell->val;

			appendStringInfoString(&sql, cell->next ? " OR " : ")");
		}

		/* Close subquery */
		appendStringInfoString(&sql, ")");
	}

	/* Ensure the regression tests get a consistent ordering of tables */
	appendStringInfoString(&sql, " ORDER BY t.relname, t.schemaname");

	/* double check the parameters array is sane */
	if (iparam != num_params)
	{
		if (errbuf)
			snprintf(errbuf, errsize,
				"internal error: bad parameters count: %i instead of %zi",
				 iparam, num_params);
		goto cleanup;
	}

	res = execute_elevel(sql.data, (int) num_params, params, DEBUG2);

	/* on error skip the database */
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		/* Return the error message otherwise */
		if (errbuf)
			snprintf(errbuf, errsize, "%s", PQerrorMessage(connection));
		goto cleanup;
	}

	num = PQntuples(res);

	for (i = 0; i < num; i++)
	{
		migrate_table	table;
		StringInfoData	copy_sql;
		const char *create_table_1;
		const char *create_table_2;
		const char *tablespace;
		const char *ckey;
		int			c = 0;
		int			dependent_views = 0;
		PGresult   *view_check_res;

		table.target_name = getstr(res, i, c++);
		elog(DEBUG2, "table: %s", table.target_name);
		table.target_oid = getoid(res, i, c++);
		table.target_toast = getoid(res, i, c++);
		table.target_tidx = getoid(res, i, c++);
		c++; // Skip schemaname
		table.pkid = getoid(res, i, c++);
		table.ckid = getoid(res, i, c++);

		if (table.pkid == 0) {
			ereport(WARNING,
					(errcode(E_PG_COMMAND),
					 errmsg("relation \"%s\" must have a primary key or not-null unique keys", table.target_name)));
			continue;
		}

		table.create_pktype = getstr(res, i, c++);
		table.create_log = getstr(res, i, c++);
		table.create_trigger = getstr(res, i, c++);
		table.enable_trigger = getstr(res, i, c++);

		create_table_1 = getstr(res, i, c++);
		tablespace = getstr(res, i, c++);	/* to be clobbered */
		create_table_2 = getstr(res, i, c++);
		table.copy_data = getstr(res, i , c++);
		table.alter_col_storage = getstr(res, i, c++);
		table.drop_columns = getstr(res, i, c++);
		table.delete_log = getstr(res, i, c++);
		table.lock_table = getstr(res, i, c++);
		ckey = getstr(res, i, c++);
		table.sql_peek = getstr(res, i, c++);
		table.sql_insert = getstr(res, i, c++);
		table.sql_delete = getstr(res, i, c++);
		table.sql_update = getstr(res, i, c++);
		table.sql_pop = getstr(res, i, c++);
		tablespace = getstr(res, i, c++);

		/* check for views referencing the table */
		resetStringInfo(&sql);
		printfStringInfo(&sql,
			"SELECT distinct v.oid::regclass AS view"
			" FROM pg_depend AS d "
			"   JOIN pg_rewrite AS r "
			"      ON r.oid = d.objid"
			"   JOIN pg_class AS v "
			"      ON v.oid = r.ev_class"
			" WHERE v.relkind = 'v'"
			"  AND d.classid = 'pg_rewrite'::regclass"
			"  AND d.refclassid = 'pg_class'::regclass"
			"  AND d.deptype = 'n'"
  			"  AND d.refobjid = '%s'::regclass",
			table.target_name);

		view_check_res = execute_elevel(sql.data, 0, NULL, DEBUG2);
		/* on error skip the table */
		if (PQresultStatus(view_check_res) != PGRES_TUPLES_OK)
		{
			/* Return the error message otherwise */
			if (errbuf)
				snprintf(errbuf, errsize, "%s", PQerrorMessage(connection));
			goto cleanup;
		}

		dependent_views = PQntuples(view_check_res);
		if (dependent_views > 0) {
			ereport(WARNING,
					(errcode(E_PG_COMMAND),
					 errmsg("the table \"%s\" has %d views depending on it. this tool does not currently support migrating tables with dependent views.", table.target_name, dependent_views)));
			CLEARPGRES(view_check_res);
			continue;
		}
		CLEARPGRES(view_check_res);

		/* Craft CREATE TABLE SQL */
		resetStringInfo(&sql);
		appendStringInfoString(&sql, create_table_1);
		appendStringInfoString(&sql, tablespace);
		appendStringInfoString(&sql, create_table_2);

		/* Always append WITH NO DATA to CREATE TABLE SQL*/
		appendStringInfoString(&sql, " WITH NO DATA");
		table.create_table = sql.data;

		/* Craft Copy SQL */
		initStringInfo(&copy_sql);
		appendStringInfoString(&copy_sql, table.copy_data);
		if (!orderby)

		{
			if (ckey != NULL)
			{
				/* CLUSTER mode */
				appendStringInfoString(&copy_sql, " ORDER BY ");
				appendStringInfoString(&copy_sql, ckey);
			}

			/* else, VACUUM FULL mode (non-clustered tables) */
		}
		else if (!orderby[0])
		{
			/* VACUUM FULL mode (for clustered tables too), do nothing */
		}
		else
		{
			/* User specified ORDER BY */
			appendStringInfoString(&copy_sql, " ORDER BY ");
			appendStringInfoString(&copy_sql, orderby);
		}
		table.copy_data = copy_sql.data;

		migrate_one_table(&table, orderby, errbuf, errsize);
	}
	ret = true;

cleanup:
	CLEARPGRES(res);
	disconnect();
	termStringInfo(&sql);
	free(params);
	return ret;
}

static int
apply_log(PGconn *conn, const migrate_table *table, int count)
{
	int			result;
	PGresult   *res;
	const char *params[6];
	char		buffer[12];

	params[0] = table->sql_peek;
	params[1] = table->sql_insert;
	params[2] = table->sql_delete;
	params[3] = table->sql_update;
	params[4] = table->sql_pop;
	params[5] = utoa(count, buffer);

	res = pgut_execute(conn,
					   "SELECT migrate.migrate_apply($1, $2, $3, $4, $5, $6)",
					   6, params);
	result = atoi(PQgetvalue(res, 0, 0));
	CLEARPGRES(res);

	return result;
}

/*
 * Create indexes on temp table, possibly using multiple worker connections
 * concurrently if the user asked for --jobs=...
 */
static bool
rebuild_indexes(const migrate_table *table)
{
	PGresult	   *res = NULL;
	int			    num_indexes;
	int				i;
	int				num_active_workers;
	int				num_workers;
	migrate_index   *index_jobs;
	bool            have_error = false;

	elog(DEBUG2, "---- create indexes ----");

	num_indexes = table->n_indexes;

	/* We might have more actual worker connections than we need,
	 * if the number of workers exceeds the number of indexes to be
	 * built. In that case, ignore the extra workers.
	 */
	num_workers = num_indexes > workers.num_workers ? workers.num_workers : num_indexes;
	num_active_workers = num_workers;

	elog(DEBUG2, "Have %d indexes and num_workers=%d", num_indexes,
		 num_workers);

	index_jobs = table->indexes;

	for (i = 0; i < num_indexes; i++)
	{

		elog(DEBUG2, "set up index_jobs [%d]", i);
		elog(DEBUG2, "target_oid   : %u", index_jobs[i].target_oid);
		elog(DEBUG2, "create_index : %s", index_jobs[i].create_index);

		if (num_workers <= 1) {
			/* Use primary connection if we are not setting up parallel
			 * index building, or if we only have one worker.
			 */
			command(index_jobs[i].create_index, 0, NULL);

			/* This bookkeeping isn't actually important in this no-workers
			 * case, but just for clarity.
			 */
			index_jobs[i].status = FINISHED;
		}
		else if (i < num_workers) {
			/* Assign available worker to build an index. */
			index_jobs[i].status = INPROGRESS;
			index_jobs[i].worker_idx = i;
			elog(LOG, "Initial worker %d to build index: %s",
				 i, index_jobs[i].create_index);

			if (!(PQsendQuery(workers.conns[i], index_jobs[i].create_index)))
			{
				elog(WARNING, "Error sending async query: %s\n%s",
					 index_jobs[i].create_index,
					 PQerrorMessage(workers.conns[i]));
				have_error = true;
				goto cleanup;
			}
		}
		/* Else we have more indexes to be built than workers
		 * available. That's OK, we'll get to them later.
		 */
	}

	if (num_workers > 1)
	{
		int freed_worker = -1;
		int ret;

/* Prefer poll() over select(), following PostgreSQL custom. */
#ifdef HAVE_POLL
		struct pollfd *input_fds;

		input_fds = pgut_malloc(sizeof(struct pollfd) * num_workers);
		for (i = 0; i < num_workers; i++)
		{
			input_fds[i].fd = PQsocket(workers.conns[i]);
			input_fds[i].events = POLLIN | POLLERR;
			input_fds[i].revents = 0;
		}
#else
		fd_set input_mask;
		struct timeval timeout;
		/* select() needs the highest-numbered socket descriptor */
		int max_fd;
#endif

		/* Now go through our index builds, and look for any which is
		 * reported complete. Reassign that worker to the next index to
		 * be built, if any.
		 */
		while (num_active_workers > 0)
		{
			elog(DEBUG2, "polling %d active workers", num_active_workers);

#ifdef HAVE_POLL
			ret = poll(input_fds, num_workers, POLL_TIMEOUT * 1000);
#else
			/* re-initialize timeout and input_mask before each
			 * invocation of select(). I think this isn't
			 * necessary on many Unixen, but just in case.
			 */
			timeout.tv_sec = POLL_TIMEOUT;
			timeout.tv_usec = 0;

			FD_ZERO(&input_mask);
			for (i = 0, max_fd = 0; i < num_workers; i++)
			{
				FD_SET(PQsocket(workers.conns[i]), &input_mask);
				if (PQsocket(workers.conns[i]) > max_fd)
					max_fd = PQsocket(workers.conns[i]);
			}

			ret = select(max_fd + 1, &input_mask, NULL, NULL, &timeout);
#endif
			/* XXX: the errno != EINTR check means we won't bail
			 * out on SIGINT. We should probably just remove this
			 * check, though it seems we also need to fix up
			 * the on_interrupt handling for workers' index
			 * builds (those PGconns don't seem to have c->cancel
			 * set, so we don't cancel the in-progress builds).
			 */
			if (ret < 0 && errno != EINTR)
				elog(ERROR, "poll() failed: %d, %d", ret, errno);

			elog(DEBUG2, "Poll returned: %d", ret);

			for (i = 0; i < num_indexes; i++)
			{
				if (index_jobs[i].status == INPROGRESS)
				{
					Assert(index_jobs[i].worker_idx >= 0);
					/* Must call PQconsumeInput before we can check PQisBusy */
					if (PQconsumeInput(workers.conns[index_jobs[i].worker_idx]) != 1)
					{
						elog(WARNING, "Error fetching async query status: %s",
							 PQerrorMessage(workers.conns[index_jobs[i].worker_idx]));
						have_error = true;
						goto cleanup;
					}
					if (!PQisBusy(workers.conns[index_jobs[i].worker_idx]))
					{
						elog(LOG, "Command finished in worker %d: %s",
							 index_jobs[i].worker_idx,
							 index_jobs[i].create_index);

						while ((res = PQgetResult(workers.conns[index_jobs[i].worker_idx])))
						{
							if (PQresultStatus(res) != PGRES_COMMAND_OK)
							{
								elog(WARNING, "Error with create index: %s",
									 PQerrorMessage(workers.conns[index_jobs[i].worker_idx]));
								have_error = true;
								goto cleanup;
							}
							CLEARPGRES(res);
						}

						/* We are only going to re-queue one worker, even
						 * though more than one index build might be finished.
						 * Any other jobs which may be finished will
						 * just have to wait for the next pass through the
						 * poll()/select() loop.
						 */
						freed_worker = index_jobs[i].worker_idx;
						index_jobs[i].status = FINISHED;
						num_active_workers--;
						break;
					}
				}
			}
			if (freed_worker > -1)
			{
				for (i = 0; i < num_indexes; i++)
				{
					if (index_jobs[i].status == UNPROCESSED)
					{
						index_jobs[i].status = INPROGRESS;
						index_jobs[i].worker_idx = freed_worker;
						elog(LOG, "Assigning worker %d to build index #%d: "
							 "%s", freed_worker, i,
							 index_jobs[i].create_index);

						if (!(PQsendQuery(workers.conns[freed_worker],
										  index_jobs[i].create_index))) {
							elog(WARNING, "Error sending async query: %s\n%s",
								 index_jobs[i].create_index,
								 PQerrorMessage(workers.conns[freed_worker]));
							have_error = true;
							goto cleanup;
						}
						num_active_workers++;
						break;
					}
				}
				freed_worker = -1;
			}
		}

	}

cleanup:
	CLEARPGRES(res);
	return (!have_error);
}


/*
 * Re-organize one table. This function contains the key
 * logic. See this blog for a walk through:
 * https://www.percona.com/blog/2021/06/24/understanding-pg_repack-what-can-go-wrong-and-how-to-avoid-it/
 */
static void
migrate_one_table(migrate_table *table, const char *orderby, char *errbuf, size_t errsize)
{
	PGresult	   *res = NULL;
	const char	   *params[3];
	int				num;
	char		   *vxid = NULL;
	char			buffer[12];
	StringInfoData	sql;
	bool            ret = false;
	PGresult       *indexres = NULL;
	const char     *indexparams[2];
	const char	   *create_table;
	char		    indexbuffer[12];
	int             j;
	migrate_foreign_key *foreign_keys;

	/* appname will be "pg_migrate" in normal use on 9.0+, or
	 * "pg_regress" when run under `make installcheck`
	 */
	const char     *appname = getenv("PGAPPNAME");

	/* Keep track of whether we have gotten through setup to install
	 * the migrate_trigger, log table, etc. ourselves. We don't want to
	 * go through migrate_cleanup() if we didn't actually set up the
	 * trigger ourselves, lest we be cleaning up another pg_migrate's mess,
	 * or worse, interfering with a still-running pg_migrate.
	 */
	bool            table_init = false;

	initStringInfo(&sql);

	elog(INFO, "migrating table \"%s\"", table->target_name);

	elog(DEBUG2, "---- migrate_one_table ----");
	elog(DEBUG2, "target_name       : %s", table->target_name);
	elog(DEBUG2, "target_oid        : %u", table->target_oid);
	elog(DEBUG2, "target_toast      : %u", table->target_toast);
	elog(DEBUG2, "target_tidx       : %u", table->target_tidx);
	elog(DEBUG2, "pkid              : %u", table->pkid);
	elog(DEBUG2, "ckid              : %u", table->ckid);
	elog(DEBUG2, "create_pktype     : %s", table->create_pktype);
	elog(DEBUG2, "create_log        : %s", table->create_log);
	elog(DEBUG2, "create_trigger    : %s", table->create_trigger);
	elog(DEBUG2, "enable_trigger    : %s", table->enable_trigger);
	elog(DEBUG2, "create_table      : %s", table->create_table);
	elog(DEBUG2, "copy_data         : %s", table->copy_data);
	elog(DEBUG2, "alter_col_storage : %s", table->alter_col_storage ?
		 table->alter_col_storage : "(skipped)");
	elog(DEBUG2, "drop_columns      : %s", table->drop_columns ? table->drop_columns : "(skipped)");
	elog(DEBUG2, "delete_log        : %s", table->delete_log);
	elog(DEBUG2, "lock_table        : %s", table->lock_table);
	elog(DEBUG2, "sql_peek          : %s", table->sql_peek);
	elog(DEBUG2, "sql_insert        : %s", table->sql_insert);
	elog(DEBUG2, "sql_delete        : %s", table->sql_delete);
	elog(DEBUG2, "sql_update        : %s", table->sql_update);
	elog(DEBUG2, "sql_pop           : %s", table->sql_pop);

	if (!execute_allowed)
		return;

	/* push migrate_cleanup_callback() on stack to clean temporary objects */
	pgut_atexit_push(migrate_cleanup_callback, &table->target_oid);

	/*
	 * 1. Setup advisory lock and trigger on main table.
	 */
	elog(DEBUG2, "---- setup triggers ----");

	params[0] = utoa(table->target_oid, buffer);

	if (!advisory_lock(connection, buffer))
		goto cleanup;

	if (!(lock_exclusive(connection, buffer, table->lock_table, true)))
	{
		if (no_kill_backend)
			elog(INFO, "Skipping migrate %s due to timeout", table->target_name);
		else
			elog(WARNING, "lock_exclusive() failed for %s", table->target_name);
		goto cleanup;
	}

	/*
	 * pg_get_indexdef requires an access share lock, so do those calls while
	 * we have an access exclusive lock anyway, so we know they won't block.
	 */
	elog(DEBUG2, "---- find indexes ----");

	indexparams[0] = utoa(table->target_oid, indexbuffer);
	indexparams[1] = moveidx ? tablespace : NULL;

	/* First, just display a warning message for any invalid indexes
	 * which may be on the table (mostly to match the behavior of 1.1.8).
	 */
	indexres = execute(
		"SELECT pg_get_indexdef(indexrelid)"
		" FROM pg_index WHERE indrelid = $1 AND NOT indisvalid",
		1, indexparams);

	for (j = 0; j < PQntuples(indexres); j++)
	{
		const char *indexdef;
		indexdef = getstr(indexres, j, 0);
		elog(WARNING, "skipping invalid index: %s", indexdef);
	}

	indexres = execute(
		"SELECT indexrelid,"
		" migrate.migrate_indexdef(indexrelid, indrelid, $2, FALSE) "
		" FROM pg_index WHERE indrelid = $1 AND indisvalid",
		2, indexparams);

	table->n_indexes = PQntuples(indexres);
	table->indexes = pgut_malloc(table->n_indexes * sizeof(migrate_index));

	for (j = 0; j < table->n_indexes; j++)
	{
		table->indexes[j].target_oid = getoid(indexres, j, 0);
		table->indexes[j].create_index = getstr(indexres, j, 1);
		table->indexes[j].status = UNPROCESSED;
		table->indexes[j].worker_idx = -1; /* Unassigned */
	}

	for (j = 0; j < table->n_indexes; j++)
	{
		elog(DEBUG2, "index[%d].target_oid      : %u", j, table->indexes[j].target_oid);
		elog(DEBUG2, "index[%d].create_index    : %s", j, table->indexes[j].create_index);
	}


	/*
	 * Check if migrate_trigger is not conflict with existing trigger. We can
	 * find it out later but we check it in advance and go to cleanup if needed.
	 * In AFTER trigger context, since triggered tuple is not changed by other
	 * trigger we don't care about the fire order.
	 */
	res = execute("SELECT migrate.conflicted_triggers($1)", 1, params);
	if (PQntuples(res) > 0)
	{
		ereport(WARNING,
				(errcode(E_PG_COMMAND),
				 errmsg("the table \"%s\" already has a trigger called \"%s\"",
						table->target_name, "migrate_trigger"),
				 errdetail(
					 "The trigger was probably installed during a previous"
					 " attempt to run pg_migrate on the table which was"
					 " interrupted and for some reason failed to clean up"
					 " the temporary objects.  Please drop the trigger or drop"
					" and recreate the pg_migrate extension altogether"
					 " to remove all the temporary objects left over.")));
		goto cleanup;
	}

	CLEARPGRES(res);

	command(table->create_pktype, 0, NULL);
	temp_obj_num++;
	command(table->create_log, 0, NULL);
	temp_obj_num++;
	command(table->create_trigger, 0, NULL);
	temp_obj_num++;
	command(table->enable_trigger, 0, NULL);
	printfStringInfo(&sql, "SELECT migrate.disable_autovacuum('migrate.log_%u')", table->target_oid);
	command(sql.data, 0, NULL);

	/* While we are still holding an AccessExclusive lock on the table, submit
	 * the request for an AccessShare lock asynchronously from conn2.
	 * We want to submit this query in conn2 while connection's
	 * transaction still holds its lock, so that no DDL may sneak in
	 * between the time that connection commits and conn2 gets its lock.
	 */
	pgut_command(conn2, "BEGIN ISOLATION LEVEL READ COMMITTED", 0, NULL);

	/* grab the backend PID of conn2; we'll need this when querying
	 * pg_locks momentarily.
	 */
	res = pgut_execute(conn2, "SELECT pg_backend_pid()", 0, NULL);
	buffer[0] = '\0';
	strncat(buffer, PQgetvalue(res, 0, 0), sizeof(buffer) - 1);
	elog(DEBUG2, "server PID of secondary connection: %s", buffer);
	CLEARPGRES(res);

	/*
	 * Not using lock_access_share() here since we know that
	 * it's not possible to obtain the ACCESS SHARE lock right now
	 * in conn2, since the primary connection holds ACCESS EXCLUSIVE.
	 */
	printfStringInfo(&sql, "LOCK TABLE %s IN ACCESS SHARE MODE",
					 table->target_name);
	elog(DEBUG2, "LOCK TABLE %s IN ACCESS SHARE MODE (secondary connection non blocking)", table->target_name);
	if (PQsetnonblocking(conn2, 1))
	{
		elog(WARNING, "Unable to set conn2 nonblocking.");
		goto cleanup;
	}
	if (!(PQsendQuery(conn2, sql.data)))
	{
		elog(WARNING, "Error sending async query: %s\n%s", sql.data,
			 PQerrorMessage(conn2));
		goto cleanup;
	}

	/* Now that we've submitted the LOCK TABLE request through conn2,
	 * look for and cancel any (potentially dangerous) DDL commands which
	 * might also be waiting on our table lock at this point --
	 * it's not safe to let them wait, because they may grab their
	 * AccessExclusive lock before conn2 gets its AccessShare lock,
	 * and perform unsafe DDL on the table.
	 *
	 * Normally, lock_access_share() would take care of this for us,
	 * but we're not able to use it here.
	 */
	if (!(kill_ddl(connection, table->target_oid, true)))
	{
		if (no_kill_backend)
			elog(INFO, "Skipping migrate %s due to timeout.", table->target_name);
		else
			elog(WARNING, "kill_ddl() failed.");
		goto cleanup;
	}

	/* We're finished killing off any unsafe DDL. COMMIT in our main
	 * connection, so that conn2 may get its AccessShare lock.
	 */
	command("COMMIT", 0, NULL);

	/* The main connection has now committed its migrate_trigger,
	 * log table, and temp. table. If any error occurs from this point
	 * on and we bail out, we should try to clean those up.
	 */
	table_init = true;

	/* Keep looping PQgetResult() calls until it returns NULL, indicating the
	 * command is done and we have obtained our lock.
	 */
	while ((res = PQgetResult(conn2)))
	{
		elog(DEBUG2, "Waiting on ACCESS SHARE lock (secondary connection)...");
		if (PQresultStatus(res) != PGRES_COMMAND_OK)
		{
			elog(WARNING, "Error with LOCK TABLE: %s", PQerrorMessage(conn2));
			goto cleanup;
		}
		CLEARPGRES(res);
	}

	/* Turn conn2 back into blocking mode for further non-async use. */
	if (PQsetnonblocking(conn2, 0))
	{
		elog(WARNING, "Unable to set conn2 blocking.");
		goto cleanup;
	}

	/*
	 * 2. Copy tuples into temp log table.
	 */
	elog(DEBUG2, "---- copy tuples ----");

	/* Must use SERIALIZABLE (or at least not READ COMMITTED) to avoid race
	 * condition between the create_table statement and rows subsequently
	 * being added to the log.
	 */
	command("BEGIN ISOLATION LEVEL SERIALIZABLE", 0, NULL);
	/* SET work_mem = maintenance_work_mem */
	command("SELECT set_config('work_mem', current_setting('maintenance_work_mem'), true)", 0, NULL);
	if (orderby && !orderby[0])
		command("SET LOCAL synchronize_seqscans = off", 0, NULL);

	/* Fetch an array of Virtual IDs of all transactions active right now.
	 */
	params[0] = buffer; /* backend PID of conn2 */
	params[1] = PROGRAM_NAME;
	res = execute(SQL_XID_SNAPSHOT, 2, params);
	vxid = pgut_strdup(PQgetvalue(res, 0, 0));

	CLEARPGRES(res);

	/* Delete any existing entries in the log table now, since we have not
	 * yet run the CREATE TABLE ... AS SELECT, which will take in all existing
	 * rows from the target table; if we also included prior rows from the
	 * log we could wind up with duplicates.
	 */
	command(table->delete_log, 0, NULL);

	/* We need to be able to obtain an AccessShare lock on the target table
	 * for the create_table command to go through, so go ahead and obtain
	 * the lock explicitly.
	 *
	 * Since conn2 has been diligently holding its AccessShare lock, it
	 * is possible that another transaction has been waiting to acquire
	 * an AccessExclusive lock on the table (e.g. a concurrent ALTER TABLE
	 * or TRUNCATE which we must not allow). If there are any such
	 * transactions, lock_access_share() will kill them so that our
	 * CREATE TABLE ... AS SELECT does not deadlock waiting for an
	 * AccessShare lock.
	 */
	if (!(lock_access_share(connection, table->target_oid, table->target_name)))
		goto cleanup;

	char *tmp_target_name = NULL;
	tmp_target_name = strdup(table->target_name);
	char *schema = strtok(tmp_target_name, ".");
	char *table_without_namespace = strtok(NULL, ".");

	/*
	 * Create the new table and apply alter statement
	 */
	elog(DEBUG2, "---- create temp table ----");
	resetStringInfo(&sql);
	/* Use a different create table statement that includes null restrictions and
	 * defaults. */
	printfStringInfo(&sql, "SELECT migrate.get_create_table_statement('%s', '%s', 'migrate.table_%u')", schema, table_without_namespace, table->target_oid);
	res = execute(sql.data, 0, NULL);

	if (PQntuples(res) < 1)
	{
		elog(WARNING,
			"unable to generate SQL to CREATE temp table");
		goto cleanup;
	}

	create_table = getstr(res, 0, 0);
	elog(DEBUG2, "--- %s", create_table);
	command(create_table, 0, NULL);

	if (!(apply_alter_statement(connection, table->target_oid, alter_list.head->val)))
		goto cleanup;

	/*
	 * Before copying data to the target table, we need to set the column storage
	 * type if its storage type has been changed from the type default.
	 */
	if (table->alter_col_storage)
		command(table->alter_col_storage, 0, NULL);


	elog(DEBUG2, "---- copy data ----");
	command(table->copy_data, 0, NULL);
	temp_obj_num++;

	printfStringInfo(&sql, "SELECT migrate.disable_autovacuum('migrate.table_%u')", table->target_oid);
	/* Note: We don't add dropped columns to the temp table because we're not
	 * swapping OIDs (the data doesn't need to match) */
	command(sql.data, 0, NULL);
	command("COMMIT", 0, NULL);

	/*
	 * 3. Create indexes on temp table.
	 */
	elog(DEBUG2, "---- create indexes on temp table ----");
	if (!rebuild_indexes(table))
		goto cleanup;

	CLEARPGRES(res);

	/*
	 * 4. Apply log to temp table until no tuples are left in the log
	 * and all of the old transactions are finished.
	 */
	elog(DEBUG2, "---- apply logs to temp table ----");
	for (;;)
	{
		num = apply_log(connection, table, APPLY_COUNT);

		/* We'll keep applying tuples from the log table in batches
		 * of APPLY_COUNT, until applying a batch of tuples
		 * (via LIMIT) results in our having applied
		 * MIN_TUPLES_BEFORE_SWITCH or fewer tuples. We don't want to
		 * get stuck repetitively applying some small number of tuples
		 * from the log table as inserts/updates/deletes may be
		 * constantly coming into the original table.
		 */
		if (num > MIN_TUPLES_BEFORE_SWITCH)
			continue;	/* there might be still some tuples, repeat. */

		/* old transactions still alive ? */
		params[0] = vxid;
		res = execute(SQL_XID_ALIVE, 1, params);
		num = PQntuples(res);

		if (num > 0)
		{
			/* Wait for old transactions.
			 * Only display this message if we are NOT
			 * running under pg_regress, so as not to cause
			 * noise which would trip up pg_regress.
			 */

			if (!appname || strcmp(appname, "pg_regress") != 0)
			{
				elog(NOTICE, "Waiting for %d transactions to finish. First PID: %s", num, PQgetvalue(res, 0, 0));
			}

			CLEARPGRES(res);
			sleep(1);
			continue;
		}
		else
		{
			/* All old transactions are finished;
			 * go to next step. */
			CLEARPGRES(res);
			break;
		}
	}

    /*
     * Get primary and foreign keys for the table before we block access.
     */
	elog(DEBUG2, "---- pre-swap: migrate foreign keys, add primary key ----");

    /* Find name of migrated index to back the primary key to avoid a duplicate index for the primary key */
    resetStringInfo(&sql);
    printfStringInfo(&sql,
            "SELECT"
            "       pg_get_indexdef(i.oid) AS indexdef,"
            "       i.relname AS indexname"
            " FROM pg_index x"
            " JOIN pg_class c ON c.oid = x.indrelid"
            " JOIN pg_class i ON i.oid = x.indexrelid"
            " LEFT JOIN pg_namespace n ON n.oid = c.relnamespace"
            " LEFT JOIN pg_tablespace t ON t.oid = i.reltablespace"
            " WHERE (c.relkind = ANY (ARRAY['r'::\"char\", 'm'::\"char\"])) AND i.relkind = 'i'::\"char\" and n.nspname = '%s' and c.relname = '%s' and indisprimary = 't'",
            schema, table_without_namespace);
    elog(DEBUG2, "--- %s", sql.data);
    res = execute_elevel(sql.data, 0, NULL, DEBUG2);
    /* on error bail */
    if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
            /* Return the error message otherwise */
            if (errbuf)
                    snprintf(errbuf, errsize, "%s", PQerrorMessage(connection));
            goto cleanup;
    }
    char *original_primary_key_def;
    const char *original_primary_key_name;
    const char *backing_index_name = NULL;
    int primary_key = PQntuples(res);

    if (primary_key > 0) {
	    original_primary_key_def = getstr(res, 0, 0);
	    original_primary_key_name = getstr(res, 0, 1);
	    CLEARPGRES(res);
	    elog(DEBUG2, "original_primary_key_def  :  %s", original_primary_key_def);
	    elog(DEBUG2, "original_primary_key_name  :  %s", original_primary_key_name);

		IndexDef		stmt;
		parse_indexdef(&stmt, original_primary_key_def, original_primary_key_name, table->target_name);
		/* iterate through indexes and see which one
		 * matches the original_primary_key_def */
		for (j = 0; j < table->n_indexes; j++)
		{
			StringInfoData	index_sql;
			initStringInfo(&index_sql);
			printfStringInfo(&index_sql, "ON migrate.table_%u USING %s (%s)%s",
				table->target_oid, stmt.type, stmt.columns, stmt.options);
			char *original_create_index = strdup(table->indexes[j].create_index);
			if (strpos(original_create_index, index_sql.data) >= 0)
			{
				resetStringInfo(&index_sql);
				printfStringInfo(&index_sql, "index_%u", table->indexes[j].target_oid);
				backing_index_name = index_sql.data;
				break;
			}
		}

		if (backing_index_name == NULL)
		{
			elog(DEBUG2, "aborting, couldn't determine migrated primary key");
			goto cleanup;
		}
	}

	/* don't clear indexes until after done accessing table->indexes or memory corrupts */
	CLEARPGRES(indexres);

	/* Find existing foreign keys. */
	resetStringInfo(&sql);
	printfStringInfo(&sql,
		"SELECT"
		"    tc.table_schema,"
		"    tc.constraint_name,"
		"    tc.table_name,"
		"    kcu.column_name,"
		"    ccu.table_schema AS foreign_table_schema,"
		"    ccu.table_name AS foreign_table_name,"
		"    ccu.column_name AS foreign_column_name"
		" FROM"
		"    information_schema.table_constraints AS tc"
		"    JOIN information_schema.key_column_usage AS kcu"
		"      ON tc.constraint_name = kcu.constraint_name"
		"      AND tc.table_schema = kcu.table_schema"
		"    JOIN information_schema.constraint_column_usage AS ccu"
		"      ON ccu.constraint_name = tc.constraint_name"
		"      AND ccu.table_schema = tc.table_schema"
		" WHERE tc.constraint_type = 'FOREIGN KEY' AND ccu.table_name ='%s' and ccu.table_schema = '%s'",
		table_without_namespace, schema);
	elog(DEBUG2, "--- %s", sql.data);
	res = execute_elevel(sql.data, 0, NULL, DEBUG2);

	/* on error bail */
	if (PQresultStatus(res) != PGRES_TUPLES_OK)
	{
		/* Return the error message otherwise */
		if (errbuf)
			snprintf(errbuf, errsize, "%s", PQerrorMessage(connection));
		goto cleanup;
	}

	num = PQntuples(res);

	/*
	 * Rebuild foreign keys so that they point to the new table.
	 */

	foreign_keys = pgut_malloc(num * sizeof(migrate_foreign_key));
	elog(DEBUG2, "foreign keys  :  found %d", num);
	for (j = 0; j < num; j++)
	{
		int			c = 0;
		foreign_keys[j].table_schema = getstr(res, j, c++);
		foreign_keys[j].constraint_name = getstr(res, j, c++);
		foreign_keys[j].table_name = getstr(res, j, c++);
		foreign_keys[j].column_name = getstr(res, j, c++);
		foreign_keys[j].foreign_table_schema = getstr(res, j, c++);
		foreign_keys[j].foreign_table_name = getstr(res, j, c++);
		foreign_keys[j].foreign_column_name = getstr(res, j, c++);

		resetStringInfo(&sql);
		printfStringInfo(&sql,
			"ALTER TABLE %s.%s ADD CONSTRAINT %s_%u "
			"FOREIGN KEY (%s) REFERENCES migrate.table_%u (%s) NOT VALID",
			foreign_keys[j].table_schema,
			foreign_keys[j].table_name,
			foreign_keys[j].constraint_name,
			table->target_oid, // TODO handle duplicate fk names/truncations from > 63 chars
			foreign_keys[j].column_name,
			table->target_oid, // instead of foreign_table_name
			foreign_keys[j].foreign_column_name);
		elog(DEBUG2, "--- %s", sql.data);
		pgut_command(conn2, sql.data, 0, NULL);

		resetStringInfo(&sql);
		/* note this DDL will be reversed if we bail because it's in a transaction */
		printfStringInfo(&sql,
			"ALTER TABLE %s.%s DROP CONSTRAINT %s",
			foreign_keys[j].table_schema,
			foreign_keys[j].table_name,
			foreign_keys[j].constraint_name);
		elog(DEBUG2, "--- %s", sql.data);
		pgut_command(conn2, sql.data, 0, NULL);
	}

	CLEARPGRES(res);

	/*
	 * 5. Swap: will be done with conn2, since it already holds an
	 *    AccessShare lock.
	 */
	elog(DEBUG2, "---- swap ----");
	/* Bump our existing AccessShare lock to AccessExclusive */
	if (!(lock_exclusive(conn2, utoa(table->target_oid, buffer),
						 table->lock_table, false)))
	{
		elog(WARNING, "lock_exclusive() failed in conn2 for %s",
			 table->target_name);
		goto cleanup;
	}

	apply_log(conn2, table, 0);

	if (primary_key > 0) {
		resetStringInfo(&sql);
		printfStringInfo(&sql, "ALTER TABLE migrate.table_%u ADD PRIMARY KEY USING INDEX %s", table->target_oid, backing_index_name);
		elog(DEBUG2, "--- %s", sql.data);
		pgut_command(conn2, sql.data, 0, NULL);
	}

	resetStringInfo(&sql);
	printfStringInfo(&sql, "ALTER TABLE %s RENAME TO %s_pre_migrate_%u", table->target_name, table_without_namespace, table->target_oid);
	elog(DEBUG2, "--- %s", sql.data);
	pgut_command(conn2, sql.data, 0, NULL);

	resetStringInfo(&sql);
	printfStringInfo(&sql, "ALTER TABLE migrate.table_%u RENAME TO %s", table->target_oid, table_without_namespace);
	elog(DEBUG2, "--- %s", sql.data);
	pgut_command(conn2, sql.data, 0, NULL);

	resetStringInfo(&sql);
	printfStringInfo(&sql, "ALTER TABLE migrate.%s SET SCHEMA %s", table_without_namespace, schema);
	elog(DEBUG2, "--- %s", sql.data);
	pgut_command(conn2, sql.data, 0, NULL);

	// TODO why didn't this work?
	// resetStringInfo(&sql);
	// printfStringInfo(&sql, "DROP TABLE %s_pre_migrate_%u", table->target_name, table->target_oid);
	// elog(DEBUG2, "--- %s", sql.data);
	// pgut_command(conn2, sql.data, 0, NULL);

	pgut_command(conn2, "COMMIT", 0, NULL);

	elog(DEBUG2, "---- validate foreign keys ----");

	// see https://travisofthenorth.com/blog/2017/2/2/postgres-adding-foreign-keys-with-zero-downtime
	for (j = 0; j < num; j++)
	{
		resetStringInfo(&sql);
		printfStringInfo(&sql,
			"ALTER TABLE %s.%s VALIDATE CONSTRAINT %s_%u",
			foreign_keys[j].table_schema,
			foreign_keys[j].table_name,
			foreign_keys[j].constraint_name,
			table->target_oid);
		elog(DEBUG2, "--- %s", sql.data);
		pgut_command(conn2, sql.data, 0, NULL);
	}

	/*
	 * 6. Drop.
	 */
	elog(DEBUG2, "---- drop ----");

	command("BEGIN ISOLATION LEVEL READ COMMITTED", 0, NULL);
	if (!(lock_exclusive(connection, utoa(table->target_oid, buffer),
						 table->lock_table, false)))
	{
		elog(WARNING, "lock_exclusive() failed in connection for %s",
			 table->target_name);
		goto cleanup;
	}

	params[0] = utoa(table->target_oid, buffer);
	params[1] = utoa(temp_obj_num, indexbuffer);
	command("SELECT migrate.migrate_drop($1, $2)", 2, params);
	command("COMMIT", 0, NULL);
	temp_obj_num = 0; /* reset temporary object counter after cleanup */

	/*
	 * 7. Analyze.
	 * Note that cleanup hook has been already uninstalled here because analyze
	 * is not an important operation; No clean up even if failed.
	 */
	if (analyze)
	{
		elog(DEBUG2, "---- analyze ----");

		command("BEGIN ISOLATION LEVEL READ COMMITTED", 0, NULL);
		printfStringInfo(&sql, "ANALYZE %s", table->target_name);
		command(sql.data, 0, NULL);
		command("COMMIT", 0, NULL);
	}

	/* Release advisory lock on table. */
	params[0] = MIGRATE_LOCK_PREFIX_STR;
	params[1] = utoa(table->target_oid, buffer);

	res = pgut_execute(connection, "SELECT pg_advisory_unlock($1, CAST(-2147483648 + $2::bigint AS integer))",
			   2, params);
	ret = true;

cleanup:
	CLEARPGRES(res);
	termStringInfo(&sql);
	if (vxid)
		free(vxid);

	/* Rollback current transactions */
	pgut_rollback(connection);
	pgut_rollback(conn2);

	/* XXX: distinguish between fatal and non-fatal errors via the first
	 * arg to migrate_cleanup().
	 */
	if ((!ret) && table_init)
		migrate_cleanup(false, table);
}

/* Kill off any concurrent DDL (or any transaction attempting to take
 * an AccessExclusive lock) trying to run against our table if we want to
 * do. Note, we're killing these queries off *before* they are granted
 * an AccessExclusive lock on our table.
 *
 * Returns true if no problems encountered, false otherwise.
 */
static bool
kill_ddl(PGconn *conn, Oid relid, bool terminate)
{
	bool			ret = true;
	PGresult	   *res;
	StringInfoData	sql;
	int				n_tuples;

	initStringInfo(&sql);

	/* Check the number of backends competing AccessExclusiveLock */
	printfStringInfo(&sql, COUNT_COMPETING_LOCKS, relid);
	res = pgut_execute(conn, sql.data, 0, NULL);
	n_tuples = PQntuples(res);

	if (n_tuples != 0)
	{
		/* Competing backend is exsits, but if we do not want to calcel/terminate
		 * any backend, do nothing.
		 */
		if (no_kill_backend)
		{
			elog(WARNING, "%d unsafe queries remain but do not cancel them and skip to migrate it",
				 n_tuples);
			ret = false;
		}
		else
		{
			resetStringInfo(&sql);
			printfStringInfo(&sql, CANCEL_COMPETING_LOCKS, relid);
			res = pgut_execute(conn, sql.data, 0, NULL);
			if (PQresultStatus(res) != PGRES_TUPLES_OK)
			{
				elog(WARNING, "Error canceling unsafe queries: %s",
					 PQerrorMessage(conn));
				ret = false;
			}
			else if (PQntuples(res) > 0 && terminate && PQserverVersion(conn) >= 80400)
			{
				elog(WARNING,
					 "Canceled %d unsafe queries. Terminating any remaining PIDs.",
					 PQntuples(res));

				CLEARPGRES(res);
				printfStringInfo(&sql, KILL_COMPETING_LOCKS, relid);
				res = pgut_execute(conn, sql.data, 0, NULL);
				if (PQresultStatus(res) != PGRES_TUPLES_OK)
				{
					elog(WARNING, "Error killing unsafe queries: %s",
						 PQerrorMessage(conn));
					ret = false;
				}
			}
			else if (PQntuples(res) > 0)
				elog(NOTICE, "Canceled %d unsafe queries", PQntuples(res));
		}
	}
	else
		elog(DEBUG2, "No competing DDL to cancel.");

	CLEARPGRES(res);
	termStringInfo(&sql);

	return ret;
}


/*
 * Try to acquire an ACCESS SHARE table lock, avoiding deadlocks and long
 * waits by killing off other sessions which may be stuck trying to obtain
 * an ACCESS EXCLUSIVE lock.
 *
 * Arguments:
 *
 *  conn: connection to use
 *  relid: OID of relation
 *  target_name: name of table
 */
static bool
lock_access_share(PGconn *conn, Oid relid, const char *target_name)
{
	StringInfoData	sql;
	time_t			start = time(NULL);
	int				i;
	bool			ret = true;

	initStringInfo(&sql);

	for (i = 1; ; i++)
	{
		time_t		duration;
		PGresult   *res;
		int			wait_msec;

		duration = time(NULL) - start;

		/* Cancel queries unconditionally, i.e. don't bother waiting
		 * wait_timeout as lock_exclusive() does -- the only queries we
		 * should be killing are disallowed DDL commands hanging around
		 * for an AccessExclusive lock, which must be deadlocked at
		 * this point anyway since conn2 holds its AccessShare lock
		 * already.
		 */
		if (duration > (wait_timeout * 2))
			ret = kill_ddl(conn, relid, true);
		else
			ret = kill_ddl(conn, relid, false);

		if (!ret)
			break;

		/* wait for a while to lock the table. */
		wait_msec = Min(1000, i * 100);
		printfStringInfo(&sql, "SET LOCAL statement_timeout = %d", wait_msec);
		pgut_command(conn, sql.data, 0, NULL);

		printfStringInfo(&sql, "LOCK TABLE %s IN ACCESS SHARE MODE", target_name);
		res = pgut_execute_elevel(conn, sql.data, 0, NULL, DEBUG2);
		if (PQresultStatus(res) == PGRES_COMMAND_OK)
		{
			CLEARPGRES(res);
			break;
		}
		else if (sqlstate_equals(res, SQLSTATE_QUERY_CANCELED))
		{
			/* retry if lock conflicted */
			CLEARPGRES(res);
			pgut_rollback(conn);
			continue;
		}
		else
		{
			/* exit otherwise */
			elog(WARNING, "%s", PQerrorMessage(connection));
			CLEARPGRES(res);
			ret = false;
			break;
		}
	}

	termStringInfo(&sql);
	pgut_command(conn, "RESET statement_timeout", 0, NULL);
	return ret;
}


static bool
apply_alter_statement(PGconn *conn, Oid relid, const char *alter_sql)
{
	StringInfoData	sql;
	time_t			start = time(NULL);
	int				i;
	bool			ret = true;
	PGresult   *res;

	initStringInfo(&sql);

	printfStringInfo(&sql, "ALTER TABLE migrate.table_%u %s", relid, alter_sql);

	elog(INFO, "%s", sql.data);
	res = pgut_execute_elevel(conn, sql.data, 0, NULL, DEBUG2);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		ret = false;
		elog(INFO, "failed to alter table");
		ereport(WARNING,
				(errcode(E_PG_COMMAND),
				 errmsg("not able to apply the alter statement, received error \"%s\"", PQerrorMessage(conn)),
				 errdetail("please debug and provide a valid alter statement")));
	}

	CLEARPGRES(res);

	return ret;
}

/* Obtain an advisory lock on the table's OID, to make sure no other
 * pg_migrate is working on the table.
 */
static bool advisory_lock(PGconn *conn, const char *relid)
{
	PGresult	   *res = NULL;
	bool			ret = false;
	const char	   *params[2];

	params[0] = MIGRATE_LOCK_PREFIX_STR;
	params[1] = relid;

	/* For the 2-argument form of pg_try_advisory_lock, we need to
	 * pass in two signed 4-byte integers. But a table OID is an
	 * *unsigned* 4-byte integer. Add -2147483648 to that OID to make
	 * it fit reliably into signed int space.
	 */
	res = pgut_execute(conn, "SELECT pg_try_advisory_lock($1, CAST(-2147483648 + $2::bigint AS integer))",
			   2, params);

	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		elog(ERROR, "%s",  PQerrorMessage(connection));
	}
	else if (strcmp(getstr(res, 0, 0), "t") != 0) {
		elog(ERROR, "Another pg_migrate command may be running on the table. Please try again later.");
	}
	else {
		ret = true;
	}
	CLEARPGRES(res);
	return ret;
}

/*
 * Try acquire an ACCESS EXCLUSIVE table lock, avoiding deadlocks and long
 * waits by killing off other sessions.
 * Arguments:
 *
 *  conn: connection to use
 *  relid: OID of relation
 *  lock_query: LOCK TABLE ... IN ACCESS EXCLUSIVE query to be executed
 *  start_xact: whether we will issue a BEGIN ourselves. If not, we will
 *              use a SAVEPOINT and ROLLBACK TO SAVEPOINT if our query
 *              times out, to avoid leaving the transaction in error state.
 */
static bool
lock_exclusive(PGconn *conn, const char *relid, const char *lock_query, bool start_xact)
{
	time_t		start = time(NULL);
	int			i;
	bool		ret = true;

	for (i = 1; ; i++)
	{
		time_t		duration;
		char		sql[1024];
		PGresult   *res;
		int			wait_msec;

		if (start_xact)
			pgut_command(conn, "BEGIN ISOLATION LEVEL READ COMMITTED", 0, NULL);
		else
			pgut_command(conn, "SAVEPOINT migrate_sp1", 0, NULL);

		duration = time(NULL) - start;
		if (duration > wait_timeout)
		{
			if (no_kill_backend)
			{
				elog(WARNING, "timed out, do not cancel conflicting backends");
				ret = false;

				/* Before exit the loop reset the transaction */
				if (start_xact)
					pgut_rollback(conn);
				else
					pgut_command(conn, "ROLLBACK TO SAVEPOINT migrate_sp1", 0, NULL);
				break;
			}
			else
			{
				const char *cancel_query;
				if (PQserverVersion(conn) >= 80400 &&
					duration > wait_timeout * 2)
				{
					elog(WARNING, "terminating conflicted backends");
					cancel_query =
						"SELECT pg_terminate_backend(pid) FROM pg_locks"
						" WHERE locktype = 'relation'"
						"   AND relation = $1 AND pid <> pg_backend_pid()";
				}
				else
				{
					elog(WARNING, "canceling conflicted backends");
					cancel_query =
						"SELECT pg_cancel_backend(pid) FROM pg_locks"
						" WHERE locktype = 'relation'"
						"   AND relation = $1 AND pid <> pg_backend_pid()";
				}

				pgut_command(conn, cancel_query, 1, &relid);
			}
		}

		/* wait for a while to lock the table. */
		wait_msec = Min(1000, i * 100);
		snprintf(sql, lengthof(sql), "SET LOCAL statement_timeout = %d", wait_msec);
		pgut_command(conn, sql, 0, NULL);

		res = pgut_execute_elevel(conn, lock_query, 0, NULL, DEBUG2);
		if (PQresultStatus(res) == PGRES_COMMAND_OK)
		{
			CLEARPGRES(res);
			break;
		}
		else if (sqlstate_equals(res, SQLSTATE_QUERY_CANCELED))
		{
			/* retry if lock conflicted */
			CLEARPGRES(res);
			if (start_xact)
				pgut_rollback(conn);
			else
				pgut_command(conn, "ROLLBACK TO SAVEPOINT migrate_sp1", 0, NULL);
			continue;
		}
		else
		{
			/* exit otherwise */
			printf("%s", PQerrorMessage(connection));
			CLEARPGRES(res);
			ret = false;
			break;
		}
	}

	pgut_command(conn, "RESET statement_timeout", 0, NULL);
	return ret;
}

static int
strpos(char *hay, char *needle)
{
   char haystack[strlen(hay)];
   strncpy(haystack, hay, strlen(hay));
   char *p = strstr(haystack, needle);
   if (p)
      return p - haystack;
   return -1;
}

// TODO import lib/migrate.h instead of duplicating these here, had a linker error
static char *
parse_error(const char * original_sql)
{
	elog(ERROR, "unexpected index definition: %s", original_sql);
	return NULL;
}

static char *
skip_const(const char * original_sql, char *sql, const char *arg1, const char *arg2)
{
	size_t	len;

	if ((arg1 && strncmp(sql, arg1, (len = strlen(arg1))) == 0) ||
		(arg2 && strncmp(sql, arg2, (len = strlen(arg2))) == 0))
	{
		sql[len] = '\0';
		return sql + len + 1;
	}

	/* error */
	return parse_error(original_sql);
}

static char *
skip_until_const(const char * original_sql, char *sql, const char *what)
{
	char *pos;

	if ((pos = strstr(sql, what)))
	{
		size_t	len;

		len = strlen(what);
		pos[-1] = '\0';
		return pos + len + 1;
	}

	/* error */
	return parse_error(original_sql);
}

static char *
skip_ident(const char * original_sql, char *sql)
{
	while (*sql && isspace((unsigned char) *sql))
		sql++;

	if (*sql == '"')
	{
		sql++;
		for (;;)
		{
			char *end = strchr(sql, '"');
			if (end == NULL)
				return parse_error(original_sql);
			else if (end[1] != '"')
			{
				end[1] = '\0';
				return end + 2;
			}
			else	/* escaped quote ("") */
				sql = end + 2;
		}
	}
	else
	{
		while (*sql && IsToken(*sql))
			sql++;
		*sql = '\0';
		return sql + 1;
	}

	/* error */
	return parse_error(original_sql);
}

/*
 * Skip until 'end' character found. The 'end' character is replaced with \0.
 * Returns the next character of the 'end', or NULL if 'end' is not found.
 */
static char *
skip_until(const char * original_sql, char *sql, char end)
{
	char	instr = 0;
	int		nopen = 0;

	for (; *sql && (nopen > 0 || instr != 0 || *sql != end); sql++)
	{
		if (instr)
		{
			if (sql[0] == instr)
			{
				if (sql[1] == instr)
					sql++;
				else
					instr = 0;
			}
			else if (sql[0] == '\\')
				sql++;	/* next char is always string */
		}
		else
		{
			switch (sql[0])
			{
				case '(':
					nopen++;
					break;
				case ')':
					nopen--;
					break;
				case '\'':
				case '"':
					instr = sql[0];
					break;
			}
		}
	}

	if (nopen == 0 && instr == 0)
	{
		if (*sql)
		{
			*sql = '\0';
			return sql + 1;
		}
		else
			return NULL;
	}

	/* error */
	return parse_error(original_sql);
}

static void
parse_indexdef(IndexDef *stmt, char *sql, const char *idxname, const char *tblname)
{
	const char *original_sql = strdup(sql);
	const char *limit = strchr(sql, '\0');

	/* CREATE [UNIQUE] INDEX */
	stmt->create = sql;
	sql = skip_const(original_sql, sql, "CREATE INDEX", "CREATE UNIQUE INDEX");
	/* index */
	stmt->index = sql;
	sql = skip_const(original_sql, sql, idxname, NULL);
	/* ON */
	sql = skip_const(original_sql, sql, "ON", NULL);
	/* table */
	stmt->table = sql;
	sql = skip_const(original_sql, sql, tblname, NULL);
	/* USING */
	sql = skip_const(original_sql, sql, "USING", NULL);
	/* type */
	stmt->type = sql;
	sql = skip_ident(original_sql, sql);
	/* (columns) */
	if ((sql = strchr(sql, '(')) == NULL)
		parse_error(original_sql);
	sql++;
	stmt->columns = sql;
	if ((sql = skip_until(original_sql, sql, ')')) == NULL)
		parse_error(original_sql);

	/* options */
	stmt->options = sql;
	stmt->tablespace = NULL;
	stmt->where = NULL;

	/* Is there a tablespace? Note that apparently there is never, but
	 * if there was one it would appear here. */
	if (sql < limit && strstr(sql, "TABLESPACE"))
	{
		sql = skip_until_const(original_sql, sql, "TABLESPACE");
		stmt->tablespace = sql;
		sql = skip_ident(original_sql, sql);
	}

	/* Note: assuming WHERE is the only clause allowed after TABLESPACE */
	if (sql < limit && strstr(sql, "WHERE"))
	{
		sql = skip_until_const(original_sql, sql, "WHERE");
		stmt->where = sql;
	}

	elog(DEBUG2, "indexdef.create  = %s", stmt->create);
	elog(DEBUG2, "indexdef.index   = %s", stmt->index);
	elog(DEBUG2, "indexdef.table   = %s", stmt->table);
	elog(DEBUG2, "indexdef.type    = %s", stmt->type);
	elog(DEBUG2, "indexdef.columns = %s", stmt->columns);
	elog(DEBUG2, "indexdef.options = %s", stmt->options);
	elog(DEBUG2, "indexdef.tspace  = %s", stmt->tablespace);
	elog(DEBUG2, "indexdef.where   = %s", stmt->where);
}

/* This function calls to migrate_drop() to clean temporary objects on error
 * in creation of temporary objects.
 */
void
migrate_cleanup_callback(bool fatal, void *userdata)
{
	Oid			target_table = *(Oid *) userdata;
	const char *params[2];
	char		buffer[12];
	char		num_buff[12];

	if(fatal)
	{
		params[0] = utoa(target_table, buffer);
		params[1] = utoa(temp_obj_num, num_buff);

		/* testing PQstatus() of connection and conn2, as we do
		 * in migrate_cleanup(), doesn't seem to work here,
		 * so just use an unconditional reconnect().
		 */
		reconnect(ERROR);
		command("SELECT migrate.migrate_drop($1, $2)", 2, params);
		temp_obj_num = 0; /* reset temporary object counter after cleanup */
	}
}

/*
 * The userdata pointing a table being re-organized. We need to cleanup temp
 * objects before the program exits.
 */
static void
migrate_cleanup(bool fatal, const migrate_table *table)
{
	if (fatal)
	{
		fprintf(stderr, "!!!FATAL ERROR!!! Please refer to the manual.\n\n");
	}
	else
	{
		char		buffer[12];
		char		num_buff[12];
		const char *params[2];

		/* Try reconnection if not available. */
		if (PQstatus(connection) != CONNECTION_OK ||
			PQstatus(conn2) != CONNECTION_OK)
			reconnect(ERROR);

		/* do cleanup */
		params[0] = utoa(table->target_oid, buffer);
		params[1] =  utoa(temp_obj_num, num_buff);
		command("SELECT migrate.migrate_drop($1, $2)", 2, params);
		temp_obj_num = 0; /* reset temporary object counter after cleanup */
	}
}

/*
 * Indexes of a table are repacked.
 */
static bool
repack_table_indexes(PGresult *index_details)
{
	bool				ret = false;
	PGresult			*res = NULL, *res2 = NULL;
	StringInfoData		sql, sql_drop;
	char				buffer[2][12];
	const char			*create_idx, *schema_name, *table_name, *params[3];
	Oid					table, index;
	int					i, num, num_repacked = 0;
	bool                *repacked_indexes;

	initStringInfo(&sql);

	num = PQntuples(index_details);
	table = getoid(index_details, 0, 3);
	params[1] = utoa(table, buffer[1]);
	params[2] = tablespace;
	schema_name = getstr(index_details, 0, 5);
	/* table_name is schema-qualified */
	table_name = getstr(index_details, 0, 4);

	/* Keep track of which of the table's indexes we have successfully
	 * repacked, so that we may DROP only those indexes.
	 */
	if (!(repacked_indexes = calloc(num, sizeof(bool))))
		ereport(ERROR, (errcode(ENOMEM),
						errmsg("Unable to calloc repacked_indexes")));

	/* Check if any concurrent pg_migrate command is being run on the same
	 * table.
	 */
	if (!advisory_lock(connection, params[1]))
		ereport(ERROR, (errcode(EINVAL),
			errmsg("Unable to obtain advisory lock on \"%s\"", table_name)));

	for (i = 0; i < num; i++)
	{
		char *isvalid = getstr(index_details, i, 2);
		char *idx_name = getstr(index_details, i, 0);

		if (isvalid[0] == 't')
		{
			index = getoid(index_details, i, 1);

			resetStringInfo(&sql);
			appendStringInfo(&sql, "SELECT pgc.relname, nsp.nspname "
							 "FROM pg_class pgc INNER JOIN pg_namespace nsp "
							 "ON nsp.oid = pgc.relnamespace "
							 "WHERE pgc.relname = 'index_%u' "
							 "AND nsp.nspname = $1", index);
			params[0] = schema_name;
			elog(INFO, "repacking index \"%s\"", idx_name);
			res = execute(sql.data, 1, params);
			if (PQresultStatus(res) != PGRES_TUPLES_OK)
			{
				elog(WARNING, "%s", PQerrorMessage(connection));
				continue;
			}
			if (PQntuples(res) > 0)
			{
				ereport(WARNING,
						(errcode(E_PG_COMMAND),
						 errmsg("Cannot create index \"%s\".\"index_%u\", "
								"already exists", schema_name, index),
						 errdetail("An invalid index may have been left behind"
								   " by a previous pg_migrate on the table"
								   " which was interrupted. Please use DROP "
								   "INDEX \"%s\".\"index_%u\""
								   " to remove this index and try again.",
								   schema_name, index)));
				continue;
			}

			if (!execute_allowed)
				continue;

			params[0] = utoa(index, buffer[0]);
			res = execute("SELECT migrate.migrate_indexdef($1, $2, $3, true)", 3,
						  params);

			if (PQntuples(res) < 1)
			{
				elog(WARNING,
					"unable to generate SQL to CREATE work index for %s",
					getstr(index_details, i, 0));
				continue;
			}

			create_idx = getstr(res, 0, 0);
			/* Use a separate PGresult to avoid stomping on create_idx */
			res2 = execute_elevel(create_idx, 0, NULL, DEBUG2);

			if (PQresultStatus(res2) != PGRES_COMMAND_OK)
			{
				ereport(WARNING,
						(errcode(E_PG_COMMAND),
						 errmsg("Error creating index \"%s\".\"index_%u\": %s",
								schema_name, index, PQerrorMessage(connection)
							 ) ));
			}
			else
			{
				repacked_indexes[i] = true;
				num_repacked++;
			}

			CLEARPGRES(res);
			CLEARPGRES(res2);
		}
		else
			elog(WARNING, "skipping invalid index: %s.%s", schema_name,
				 getstr(index_details, i, 0));
	}

	if (!execute_allowed) {
		ret = true;
		goto done;
	}

	/* If we did not successfully repack any indexes, e.g. because of some
	 * error affecting every CREATE INDEX attempt, don't waste time with
	 * the ACCESS EXCLUSIVE lock on the table, and return false.
	 * N.B. none of the DROP INDEXes should be performed since
	 * repacked_indexes[] flags should all be false.
	 */
	if (!num_repacked)
	{
		elog(WARNING,
			 "Skipping index swapping for \"%s\", since no new indexes built",
			 table_name);
		goto drop_idx;
	}

	/* take an exclusive lock on table before calling migrate_index_swap() */
	resetStringInfo(&sql);
	appendStringInfo(&sql, "LOCK TABLE %s IN ACCESS EXCLUSIVE MODE",
					 table_name);
	if (!(lock_exclusive(connection, params[1], sql.data, true)))
	{
		elog(WARNING, "lock_exclusive() failed in connection for %s",
			 table_name);
		goto drop_idx;
	}

	for (i = 0; i < num; i++)
	{
		index = getoid(index_details, i, 1);
		if (repacked_indexes[i])
		{
			params[0] = utoa(index, buffer[0]);
			pgut_command(connection, "SELECT migrate.migrate_index_swap($1)", 1,
						 params);
		}
		else
			elog(INFO, "Skipping index swap for index_%u", index);
	}
	pgut_command(connection, "COMMIT", 0, NULL);
	ret = true;

drop_idx:
	resetStringInfo(&sql);
	initStringInfo(&sql_drop);
	appendStringInfoString(&sql, "DROP INDEX CONCURRENTLY ");
	appendStringInfo(&sql, "\"%s\".",  schema_name);

	for (i = 0; i < num; i++)
	{
		index = getoid(index_details, i, 1);
		if (repacked_indexes[i])
		{
			initStringInfo(&sql_drop);
			appendStringInfo(&sql_drop, "%s\"index_%u\"", sql.data, index);
			command(sql_drop.data, 0, NULL);
		}
		else
			elog(INFO, "Skipping drop of index_%u", index);
	}
	termStringInfo(&sql_drop);
	termStringInfo(&sql);

done:
	CLEARPGRES(res);
	free(repacked_indexes);

	return ret;
}

/*
 * Call repack_table_indexes for each of the tables
 */
static bool
repack_all_indexes(char *errbuf, size_t errsize)
{
	bool					ret = false;
	PGresult				*res = NULL;
	StringInfoData			sql;
	SimpleStringListCell	*cell = NULL;
	const char				*params[1];

	initStringInfo(&sql);
	reconnect(ERROR);

	assert(r_index.head || table_list.head || parent_table_list.head);

	if (!preliminary_checks(errbuf, errsize))
		goto cleanup;

	if (!is_requested_relation_exists(errbuf, errsize))
		goto cleanup;

	if (r_index.head)
	{
		appendStringInfoString(&sql,
			"SELECT migrate.oid2text(i.oid), idx.indexrelid, idx.indisvalid, idx.indrelid, migrate.oid2text(idx.indrelid), n.nspname"
			" FROM pg_index idx JOIN pg_class i ON i.oid = idx.indexrelid"
			" JOIN pg_namespace n ON n.oid = i.relnamespace"
			" WHERE idx.indexrelid = $1::regclass ORDER BY indisvalid DESC, i.relname, n.nspname");

		cell = r_index.head;
	}
	else if (table_list.head || parent_table_list.head)
	{
		appendStringInfoString(&sql,
			"SELECT migrate.oid2text(i.oid), idx.indexrelid, idx.indisvalid, idx.indrelid, $1::text, n.nspname"
			" FROM pg_index idx JOIN pg_class i ON i.oid = idx.indexrelid"
			" JOIN pg_namespace n ON n.oid = i.relnamespace"
			" WHERE idx.indrelid = $1::regclass ORDER BY indisvalid DESC, i.relname, n.nspname");

		for (cell = parent_table_list.head; cell; cell = cell->next)
		{
			int nchildren, i;

			params[0] = cell->val;

			/* find children of this parent table */
			res = execute_elevel("SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname)"
								 " FROM pg_class c JOIN pg_namespace n on n.oid = c.relnamespace"
								 " WHERE c.oid = ANY (migrate.get_table_and_inheritors($1::regclass))"
								 " ORDER BY n.nspname, c.relname", 1, params, DEBUG2);

			if (PQresultStatus(res) != PGRES_TUPLES_OK)
			{
				elog(WARNING, "%s", PQerrorMessage(connection));
				continue;
			}

			nchildren = PQntuples(res);

			if (nchildren == 0)
			{
				elog(WARNING, "relation \"%s\" does not exist", cell->val);
				continue;
			}

			/* append new tables to 'table_list' */
			for (i = 0; i < nchildren; i++)
				simple_string_list_append(&table_list, getstr(res, i, 0));
		}

		CLEARPGRES(res);

		cell = table_list.head;
	}

	for (; cell; cell = cell->next)
	{
		params[0] = cell->val;
		res = execute_elevel(sql.data, 1, params, DEBUG2);

		if (PQresultStatus(res) != PGRES_TUPLES_OK)
		{
			elog(WARNING, "%s", PQerrorMessage(connection));
			continue;
		}

		if (PQntuples(res) == 0)
		{
			if(table_list.head)
				elog(WARNING, "\"%s\" does not have any indexes",
					cell->val);
			else if(r_index.head)
				elog(WARNING, "\"%s\" is not a valid index",
					cell->val);

			continue;
		}

		if(table_list.head)
			elog(INFO, "repacking indexes of \"%s\"", cell->val);

		if (!repack_table_indexes(res))
			elog(WARNING, "repack failed for \"%s\"", cell->val);

		CLEARPGRES(res);
	}
	ret = true;

cleanup:
	disconnect();
	termStringInfo(&sql);
	return ret;
}

void
pgut_help(bool details)
{
	printf("%s migrates a PostgreSQL table avoiding long locks.\n\n", PROGRAM_NAME);
	printf("Usage:\n");
	printf("  %s [OPTION]... [DBNAME]\n", PROGRAM_NAME);

	if (!details)
		return;

	printf("Options:\n");
	printf("  -t, --table=TABLE         table to target\n");
	printf("  -d, --database=DATABASE   database in which the table lives\n");
	printf("  -a, --alter=ALTER         SQL of the alter statement\n");
	printf("  -N, --execute             whether to run the migration\n");
	printf("  -j, --jobs=NUM            Use this many parallel jobs for each table\n");
	printf("  -T, --wait-timeout=SECS   timeout to cancel other backends on conflict\n");
	printf("  -D, --no-kill-backend     don't kill other backends when timed out\n");
	printf("  -k, --no-superuser-check  skip superuser checks in client\n");
}
