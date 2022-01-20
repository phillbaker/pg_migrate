#
# pg_migrate: bin/Makefile
#
#  Portions Copyright (c) 2008-2012, NIPPON TELEGRAPH AND TELEPHONE CORPORATION
#  Portions Copyright (c) 2011, Itagaki Takahiro
#  Portions Copyright (c) 2012-2020, The Reorg Development Team
#

PG_CONFIG ?= pg_config

SRCS = pg_migrate.c pgut/pgut.c pgut/pgut-fe.c
OBJS = $(SRCS:.c=.o)
PROGRAM = pg_migrate


# The version number of the program. It should be the same of the library.
MIGRATE_VERSION = $(shell grep '"version":' ../META.json | head -1 \
	| sed -e 's/[ 	]*"version":[ 	]*"\(.*\)",/\1/')

PG_CPPFLAGS = -I$(libpq_srcdir) -DMIGRATE_VERSION=$(MIGRATE_VERSION)

ifdef DEBUG_MIGRATE
PG_CPPFLAGS += -DDEBUG_MIGRATE
endif

PG_LIBS = $(libpq)

# libs pgport, pgcommon moved somewhere else in some ubuntu version
# see ticket #179
PG_LIBS += -L$(shell $(PG_CONFIG) --pkglibdir)

USE_PGXS = 1	# use pgxs if not in contrib directory
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# remove dependency on libxml2, libxslt, and libpam.
# XXX: find a better way to make sure we are linking with libraries
# from pg_config which we actually need.
LIBS := $(filter-out -ledit -lgssapi_krb5 -lpam -lselinux -lxml2 -lxslt, $(LIBS))
