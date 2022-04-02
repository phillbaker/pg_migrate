class PgMigratePostgresqlAT10 < Formula
  desc "PostgreSQL 10 extension and CLI to make schema changes with minimal locks"
  homepage "https://github.com/phillbaker/pg_migrate"
  url "https://github.com/phillbaker/pg_migrate/releases/download/v0.1.0/pg_migrate-0.1.0.zip"
  sha256 "7b4d7fe8d4cd47e235e3d689cc4cfd712ec3146e834958349715583f4bbe5784"
  license "BSD-3-Clause"
  head "https://github.com/phillbaker/pg_migrate", using: :git, branch: "master"

  depends_on "postgresql@10"

  def install
    ENV.prepend "LDFLAGS", "-L#{Formula["postgresql@10"].opt_lib}"
    ENV.prepend "CPPFLAGS", "-I#{Formula["postgresql@10"].opt_include}"
    ENV.prepend "PKG_CONFIG_PATH", "-I#{Formula["postgresql@10"].opt_lib}/pkgconfig"

    system "make"

    bin.install "./bin/pg_migrate"
  end

  def caveats
    <<~EOS
      To use this on a locally running version of postgres, please install the extension files:

      cp #{lib}/pg_migrate.so #{Formula["postgresql@10"].lib}
      cp #{lib}/pg_migrate--#{version}.sql #{Formula["postgresql@10"].share}/postgresql@10/extension/
      cp #{lib}/pg_migrate.control #{Formula["postgresql@10"].share}/postgresql@10/extension/

      Then run:
      `psql -c "DROP EXTENSION IF EXISTS pg_migrate cascade; CREATE EXTENSION pg_migrate" -d postgres`
    EOS
  end

  test do
    system bin/"pg_migrate", "--version"
  end
end
