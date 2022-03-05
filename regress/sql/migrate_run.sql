--
-- do migration
--

\! pg_migrate --dbname=contrib_regression --table=tbl_cluster --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_badindex --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_gistkey --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_only_ckey --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_idxopts --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_only_pkey --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_order --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_with_dropped_column --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_with_dropped_toast --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_with_view --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_with_mod_column_storage --alter='ADD COLUMN a1 INT' --execute
\! pg_migrate --dbname=contrib_regression --table=tbl_with_toast --alter='ADD COLUMN a1 INT' --execute
