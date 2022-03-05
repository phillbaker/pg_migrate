SET client_min_messages = warning;

--
-- Tablespace features tests
--

DROP TABLESPACE IF EXISTS testts;
\! mkdir -p /tmp/pg-migrate-tablespace
CREATE TABLESPACE testts LOCATION '/tmp/pg-migrate-tablespace';

SELECT spcname FROM pg_tablespace WHERE spcname = 'testts';
-- If the query above failed you must create the 'testts' tablespace;

CREATE TABLE testts1 (id serial primary key, data text);
CREATE INDEX testts1_partial_idx on testts1 (id) where (id > 0);
CREATE INDEX testts1_with_idx on testts1 (id) with (fillfactor=80);
INSERT INTO testts1 (data) values ('a');
INSERT INTO testts1 (data) values ('b');
INSERT INTO testts1 (data) values ('c');

-- check the indexes definitions
SELECT regexp_replace(
    migrate.migrate_indexdef(indexrelid, 'testts1'::regclass, NULL, false, 'hash'),
    '_[0-9]+', '_OID', 'g')
FROM pg_index i join pg_class c ON c.oid = indexrelid
WHERE indrelid = 'testts1'::regclass ORDER BY relname;

SELECT regexp_replace(
    migrate.migrate_indexdef(indexrelid, 'testts1'::regclass, 'foo', false, 'hash'),
    '_[0-9]+', '_OID', 'g')
FROM pg_index i join pg_class c ON c.oid = indexrelid
WHERE indrelid = 'testts1'::regclass ORDER BY relname;

SELECT regexp_replace(
    migrate.migrate_indexdef(indexrelid, 'testts1'::regclass, NULL, true, 'hash'),
    '_[0-9]+', '_OID', 'g')
FROM pg_index i join pg_class c ON c.oid = indexrelid
WHERE indrelid = 'testts1'::regclass ORDER BY relname;

SELECT regexp_replace(
    migrate.migrate_indexdef(indexrelid, 'testts1'::regclass, 'foo', true, 'hash'),
    '_[0-9]+', '_OID', 'g')
FROM pg_index i join pg_class c ON c.oid = indexrelid
WHERE indrelid = 'testts1'::regclass ORDER BY relname;

-- can specify the tablespace, other than default
\! pg_migrate --dbname=contrib_regression --table=testts1 --tablespace testts --alter='ADD COLUMN a1 INT' --execute

SELECT relname, spcname
FROM pg_class JOIN pg_tablespace ts ON ts.oid = reltablespace
WHERE relname ~ '^testts1' AND NOT relname ~ '^testts1_pre_migrate'
ORDER BY relname;

SELECT * from testts1 order by id;

-- tablespace stays where it is
\! pg_migrate --dbname=contrib_regression --table=testts1 --alter='ADD COLUMN a2 INT' --execute

SELECT relname, spcname
FROM pg_class JOIN pg_tablespace ts ON ts.oid = reltablespace
WHERE relname ~ '^testts1' AND NOT relname ~ '^testts1_pre_migrate'
ORDER BY relname;

-- can move the tablespace back to default
\! pg_migrate --dbname=contrib_regression --table=testts1 -s pg_default --alter='ADD COLUMN a3 INT' --execute

SELECT relname, spcname
FROM pg_class JOIN pg_tablespace ts ON ts.oid = reltablespace
WHERE relname ~ '^testts1' AND NOT relname ~ '^testts1_pre_migrate'
ORDER BY relname;

-- can move the table together with the indexes
\! pg_migrate --dbname=contrib_regression --table=testts1 --tablespace testts --alter='ADD COLUMN a4 INT' --execute

SELECT relname, spcname
FROM pg_class JOIN pg_tablespace ts ON ts.oid = reltablespace
WHERE relname ~ '^testts1' AND NOT relname ~ '^testts1_pre_migrate'
ORDER BY relname;
