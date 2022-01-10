pg_migrate -- Reorganize tables in PostgreSQL databases with minimal locks
=========================================================================

- Homepage:
- Download:
- Development:
- Bug Report:

|travis|

.. |travis| image:: https://travis-ci.org/reorg/pg_repack.svg?branch=master
    :target: https://travis-ci.org/reorg/pg_repack
    :alt: Linux and OSX build status

pg_migrate is a PostgreSQL extension which lets you make schema changes to
tables and indexes. Unlike `ALTER TABLE` it works online, without
holding an exclusive lock on the processed tables during processing.

Please check the documentation (in the ``doc`` directory or online) for
installation and usage instructions.

Forked from the excellent pg_repack project (https://reorg.github.io/pg_repack).
