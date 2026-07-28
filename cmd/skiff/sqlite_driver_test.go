package main

import (
	"database/sql"
	"slices"
	"testing"
)

// Guards against a future `go mod tidy` dropping the modernc.org/sqlite
// dependency. go-rpmdb's SQLite3 backend opens its DB via sql.Open("sqlite", ...),
// which only works if a driver registered under that exact name is linked.
func TestSqliteDriverRegistered(t *testing.T) {
	if !slices.Contains(sql.Drivers(), "sqlite") {
		t.Fatalf("expected %q driver to be registered, have %v", "sqlite", sql.Drivers())
	}
}
