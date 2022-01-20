# pg_migrate -- Reorganize tables in PostgreSQL databases with minimal locks

- Documentation:
- Download:
- Development:
- Bug Reports:

|travis|

.. |travis| image:: https://travis-ci.org/reorg/pg_repack.svg?branch=master
    :target: https://travis-ci.org/reorg/pg_repack
    :alt: Linux and OSX build status

## About

pg_migrate is a PostgreSQL extension which lets you make schema changes to
tables and indexes. Unlike `ALTER TABLE` it works online, without
holding a long lived exclusive lock on the processed tables during the migration. It builds a copy of the target table and swaps them.

Please check the documentation (in the ``doc`` directory or online) for
installation and usage instructions.

Forked from the excellent pg_repack project (https://reorg.github.io/pg_repack).

## Supported Postgres Versions

Postgres >= 9.6

## Known Limitations

* Unique constraints are converted into unique indexes, [they are equivalent in Postgres](https://stackoverflow.com/questions/23542794/postgres-unique-constraint-vs-index). However, this may be an unexpected change.
* Index names on the target table and foreign key constraints are changed during the migration.
  * If the generated names are > 63 characters, this will likely break
* If the target table is used in views, those objects will continue to reference the original table - this is not supported currently.
  * If the target table is used in stored procedures, those functions are stored as text so are not linked through object IDs and will reference the migrated table.
* DDL to drop columns or add columns without a default is not currently supported

