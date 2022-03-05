--
-- no superuser check
--
SET client_min_messages = error;
DROP ROLE IF EXISTS nosuper;
SET client_min_messages = warning;
CREATE ROLE nosuper WITH LOGIN;
-- => OK
\! pg_migrate --execute --alter='ADD COLUMN ns1 INT' --dbname=contrib_regression --table=tbl_cluster --no-superuser-check
-- => ERROR
\! pg_migrate --execute --alter='ADD COLUMN ns2 INT' --dbname=contrib_regression --table=tbl_cluster --username=nosuper
-- => ERROR
\! pg_migrate --execute --alter='ADD COLUMN ns3 INT' --dbname=contrib_regression --table=tbl_cluster --username=nosuper --no-superuser-check
DROP ROLE IF EXISTS nosuper;
