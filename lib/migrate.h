#ifndef MIGRATE_H
#define MIGRATE_H

/*
 * Parsed CREATE INDEX statement. You can rebuild sql using
 * sprintf(buf, "%s %s ON %s USING %s (%s)%s",
 *		create, index, table type, columns, options)
 */
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

extern char *skip_const(const char *original_sql, char *sql, const char *arg1, const char *arg2);
extern char *skip_ident(const char *original_sql, char *sql);
extern char *parse_error(const char *original_sql);
extern char *skip_until_const(const char *original_sql, char *sql, const char *what);
extern char *skip_until(const char *original_sql, char *sql, char end);

#endif
