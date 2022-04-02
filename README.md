# pg_migrate -- Perform schema changes in PostgreSQL with minimal locks

- Download: https://github.com/phillbaker/pg_migrate/releases
- Development: https://github.com/phillbaker/pg_migrate
- Bug Reports: https://github.com/phillbaker/pg_migrate/issues



## About

pg_migrate is a PostgreSQL extension and CLI which lets you make schema
changes to tables and indexes. Unlike `ALTER TABLE` it works online, without
holding a long lived exclusive lock on the processed tables during the
migration. It builds a copy of the target table and swaps them.

Please check the documentation (in the ``doc`` directory or online) for
installation and usage instructions.

Forked from the excellent pg_repack project (https://reorg.github.io/pg_repack).

## Supported Postgres Versions

Postgres >= 9.6

## Installation

### Ubuntu/Debian

Use `apt-get` to install the package matching the Postgres version (`postgresql-<version>-pg_migrate`) being run from [this repo's APT repository](https://github.com/phillbaker/pg_migrate/releases/tag/apt-release-amd64).

To add to your `/etc/apt/sources.list.d`, add the signing GPG key, and update the package DB, run:

```
curl -L https://github.com/phillbaker/pg_migrate/releases/download/apt-release-amd64/apt-add-repo | sh
```

Then to install, for example, for Postgres 10:
```
apt-get install -y postgresql-10-pg_migrate
```

Load the pg_migrate Postgres extension in the database you want to work on:
```
psql -c "DROP EXTENSION IF EXISTS pg_migrate cascade; CREATE EXTENSION pg_migrate" -d postgres
```

### Mac

Use `homebrew` to install the package matching the Postgres version being used.

```
brew tap phillbaker/pg_migrate https://github.com/phillbaker/pg_migrate
brew install pg_migrate_postgresql@10
# follow the post install instructions if you're running postgres on your local machine
```

## Examples

### Change the type of a column

```
pg_migrate --table=my_table --alter='ALTER COLUMN id TYPE bigint' # Add --execute to run
```

### Add a column with a default (non-nullable)

```
pg_migrate --table=my_table --alter='ADD COLUMN foo integer NOT NULL DEFAULT 42' # Add --execute to run
```

## Known Limitations

* Unique constraints are converted into unique indexes, [they are equivalent in Postgres](https://stackoverflow.com/questions/23542794/postgres-unique-constraint-vs-index). However, this may be an unexpected change.
* Index names on the target table and foreign key constraints are changed during the migration.
  * If the generated names are > 63 characters, this will likely break
* If the target table is used in views, those objects will continue to reference the original table - this is not supported currently.
  * If the target table is used in stored procedures, those functions are stored as text so are not linked through object IDs and will reference the migrated table.
* DDL to drop columns or add columns without a default is not currently supported
* Hosted PG databases (RDS, Cloud SQL) are not supported because they do not allow installing custom extensions.

